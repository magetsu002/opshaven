#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import stat
import sys
import tempfile

RUNTIME_ROOT = pathlib.Path("/usr/lib/opshaven")
MANIFEST_PATH = pathlib.Path("/var/lib/opshaven/runtime-manifest.json")
RECEIPT_PATH = pathlib.Path("/var/lib/opshaven/setup-receipt.json")
TRANSACTION_PATH = pathlib.Path("/var/lib/opshaven/synchronization-transaction.json")
CONTROLLED_RELATIVE = "src/remote/dispatcher.js"
READ_ONLY_RELATIVE = "src/remote/read-only-dispatcher.js"


def fail(message):
    raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_file(file_path, maximum=16 * 1024 * 1024):
    info = os.lstat(file_path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > maximum:
        fail("unsafe dispatcher artifact")
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def read_json(file_path, maximum=2 * 1024 * 1024):
    sha256_file(file_path, maximum)
    with open(file_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def atomic_json(value, destination, mode=0o600):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.opshaven-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(canonical(value) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, 0, 0)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_dispatcher(source, destination):
    descriptor, temporary = tempfile.mkstemp(prefix=".dispatcher.opshaven-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as output, open(source, "rb") as input_handle:
            shutil.copyfileobj(input_handle, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o755)
        os.chown(temporary, 0, 0)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def valid_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def verify_manifest(manifest):
    if not isinstance(manifest, dict) or set(manifest.keys()) != {"version", "files", "treeSha256"} or manifest.get("version") != 1:
        fail("runtime manifest schema is invalid")
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > 4096:
        fail("runtime manifest file list is invalid")
    canonical_files = []
    for item in files:
        if not isinstance(item, dict) or set(item.keys()) != {"path", "sha256", "executable"}:
            fail("runtime manifest entry is invalid")
        if not isinstance(item.get("path"), str) or item["path"].startswith("/") or ".." in pathlib.PurePosixPath(item["path"]).parts:
            fail("runtime manifest path is invalid")
        if not valid_digest(item.get("sha256")) or not isinstance(item.get("executable"), bool):
            fail("runtime manifest identity is invalid")
        canonical_files.append({"executable": item["executable"], "path": item["path"], "sha256": item["sha256"]})
    tree = hashlib.sha256(json.dumps(canonical_files, separators=(",", ":")).encode("utf-8")).hexdigest()
    if tree != manifest.get("treeSha256"):
        fail("runtime manifest tree identity is invalid")
    return files


def load_plan(stage):
    plan = read_json(stage / "plan.json")
    expected = {
        "version",
        "stageRoot",
        "transactionPath",
        "transactionId",
        "sourceSha",
        "runtimeRoot",
        "manifestPath",
        "receiptPath",
        "dispatcherRelative",
        "expectedDispatcherSha256",
        "desiredDispatcherSha256",
    }
    if not isinstance(plan, dict) or set(plan.keys()) != expected or plan.get("version") != 1:
        fail("dispatcher plan schema is invalid")
    fixed = {
        "stageRoot": str(stage),
        "transactionPath": str(TRANSACTION_PATH),
        "runtimeRoot": str(RUNTIME_ROOT),
        "manifestPath": str(MANIFEST_PATH),
        "receiptPath": str(RECEIPT_PATH),
        "dispatcherRelative": CONTROLLED_RELATIVE,
    }
    for key, value in fixed.items():
        if plan.get(key) != value:
            fail(f"dispatcher plan changed fixed field {key}")
    if not isinstance(plan.get("transactionId"), str) or len(plan["transactionId"]) != 32 or any(char not in "0123456789abcdef" for char in plan["transactionId"]):
        fail("dispatcher transaction identity is invalid")
    if not isinstance(plan.get("sourceSha"), str) or len(plan["sourceSha"]) != 40 or any(char not in "0123456789abcdef" for char in plan["sourceSha"]):
        fail("dispatcher source identity is invalid")
    if not valid_digest(plan.get("expectedDispatcherSha256")) or not valid_digest(plan.get("desiredDispatcherSha256")):
        fail("dispatcher artifact identity is invalid")
    return plan


def verify_transaction(plan):
    transaction = read_json(TRANSACTION_PATH)
    integrity = transaction.pop("integritySha256", None)
    if not valid_digest(integrity) or hashlib.sha256(canonical(transaction).encode("utf-8")).hexdigest() != integrity:
        fail("synchronization transaction integrity mismatch")
    if transaction.get("version") != 1 or transaction.get("transactionId") != plan["transactionId"] or transaction.get("phase") != "ACTIVATE":
        fail("dispatcher activation is not bound to the active synchronization transaction")
    previous = transaction.get("previousGenerationIdentity")
    if previous is not None and not valid_digest(previous):
        fail("previous generation identity is invalid")
    return transaction


def main():
    if os.geteuid() != 0:
        fail("dispatcher installer must run as root")
    if len(sys.argv) != 2:
        fail("dispatcher installer requires one staged directory")
    stage = pathlib.Path(sys.argv[1])
    if not stage.is_absolute() or stage.parent != pathlib.Path("/tmp") or stage.is_symlink() or not stage.is_dir():
        fail("dispatcher stage is invalid")
    plan = load_plan(stage)
    transaction = verify_transaction(plan)
    staged = stage / "dispatcher.js"
    if sha256_file(staged) != plan["desiredDispatcherSha256"]:
        fail("staged dispatcher identity mismatch")
    if RUNTIME_ROOT.is_symlink() or not RUNTIME_ROOT.is_dir():
        fail("installed runtime root is unsafe")
    controlled = RUNTIME_ROOT / CONTROLLED_RELATIVE
    read_only = RUNTIME_ROOT / READ_ONLY_RELATIVE
    candidates = [item for item in (controlled, read_only) if item.exists()]
    if len(candidates) != 1 or sha256_file(candidates[0]) != plan["expectedDispatcherSha256"]:
        fail("installed dispatcher changed after inspection")
    manifest = read_json(MANIFEST_PATH)
    files = verify_manifest(manifest)
    destination = controlled
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        fail("dispatcher destination directory is unsafe")
    atomic_dispatcher(staged, destination)
    if read_only.exists():
        if read_only.is_symlink() or not read_only.is_file():
            fail("legacy dispatcher path is unsafe")
        read_only.unlink()
    updated = [item for item in files if item["path"] not in (CONTROLLED_RELATIVE, READ_ONLY_RELATIVE)]
    updated.append({"path": CONTROLLED_RELATIVE, "sha256": plan["desiredDispatcherSha256"], "executable": True})
    updated.sort(key=lambda item: item["path"])
    canonical_files = [{"executable": item["executable"], "path": item["path"], "sha256": item["sha256"]} for item in updated]
    manifest = {"version": 1, "files": updated, "treeSha256": hashlib.sha256(json.dumps(canonical_files, separators=(",", ":")).encode("utf-8")).hexdigest()}
    atomic_json(manifest, MANIFEST_PATH)
    receipt = read_json(RECEIPT_PATH)
    if receipt.get("version") != 1 or not isinstance(receipt.get("receiptId"), str) or not receipt["receiptId"].isalnum():
        fail("installed generation receipt is invalid")
    receipt["sourceSha"] = plan["sourceSha"]
    receipt["runtimeTreeSha256"] = manifest["treeSha256"]
    receipt["certified"] = False
    receipt["transactionId"] = plan["transactionId"]
    receipt["previousGenerationIdentity"] = transaction.get("previousGenerationIdentity")
    receipt["dispatcherSha256"] = plan["desiredDispatcherSha256"]
    atomic_json(receipt, RECEIPT_PATH)
    print(canonical({
        "ok": True,
        "transactionId": plan["transactionId"],
        "dispatcherSha256": plan["desiredDispatcherSha256"],
        "runtimeTreeSha256": manifest["treeSha256"],
        "changed": [str(destination), str(MANIFEST_PATH), str(RECEIPT_PATH)],
        "dependencyInstall": False,
    }))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        sys.exit(1)
