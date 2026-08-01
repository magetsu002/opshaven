#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile

CONFIG = pathlib.Path("/etc/opshaven/config.json")
DESTINATIONS = {
    "remote-config.json": (CONFIG, 0o644),
    "operator-public.pem": (pathlib.Path("/etc/opshaven/approval-public.pem"), 0o644),
    "capability.json": (pathlib.Path(f"{CONFIG}.capability.json"), 0o644),
    "declaration.json": (pathlib.Path(f"{CONFIG}.declaration.json"), 0o644),
    "binding.json": (pathlib.Path(f"{CONFIG}.declaration-binding.json"), 0o644),
}
RESPONSE_PRIVATE = pathlib.Path(f"{CONFIG}.response-private.pem")
RESPONSE_PUBLIC = pathlib.Path(f"{CONFIG}.response-public.pem")
BACKUP_PARENT = pathlib.Path("/var/lib/opshaven/backups")
RECEIPT = pathlib.Path("/var/lib/opshaven/setup-receipt.json")


def fail(message):
    raise RuntimeError(message)


def regular(file_path, maximum=1048576):
    info = os.lstat(file_path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > maximum:
        fail(f"unsafe regular file: {file_path}")


def directory(directory_path):
    info = os.lstat(directory_path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        fail(f"unsafe directory: {directory_path}")


def sha256_file(file_path):
    regular(file_path)
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        while True:
            chunk = handle.read(1048576)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def backup_path(destination, backup_root):
    return backup_root / str(destination).lstrip("/")


def backup_existing(destination, backup_root):
    if not destination.exists():
        return None
    regular(destination)
    original = os.lstat(destination)
    backup = backup_path(destination, backup_root)
    backup.parent.mkdir(parents=True, exist_ok=True)
    if backup.exists():
        fail(f"trust backup already exists: {backup}")
    shutil.copy2(destination, backup, follow_symlinks=False)
    os.chmod(backup, stat.S_IMODE(original.st_mode))
    os.chown(backup, original.st_uid, original.st_gid)
    return backup


def atomic_copy(source, destination, mode, uid=0, gid=0):
    regular(source)
    directory(destination.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".opshaven-trust-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as output, open(source, "rb") as input_handle:
            shutil.copyfileobj(input_handle, output, 1048576)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(value, destination):
    directory(destination.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".opshaven-receipt-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.chown(temporary, 0, 0)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install_changed(source, destination, mode, backup_root, journal, changed, uid=0, gid=0):
    source_hash = sha256_file(source)
    if destination.exists():
        regular(destination)
        if sha256_file(destination) == source_hash:
            os.chmod(destination, mode)
            os.chown(destination, uid, gid)
            return
    backup = backup_existing(destination, backup_root)
    journal.append((destination, backup))
    atomic_copy(source, destination, mode, uid, gid)
    changed.append(str(destination))


def restore(journal):
    for destination, backup in reversed(journal):
        if destination.exists():
            regular(destination)
            destination.unlink()
        if backup is not None and backup.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(backup, destination)


def load_plan(stage):
    plan_path = stage / "trust-plan.json"
    regular(plan_path)
    with open(plan_path, "r", encoding="utf-8") as handle:
        plan = json.load(handle)
    expected = {"version", "stageRoot", "backupRoot", "receiptPath", "receiptId", "sourceSha"}
    if not isinstance(plan, dict) or set(plan.keys()) != expected or plan.get("version") != 1:
        fail("trust plan schema is invalid")
    if plan.get("stageRoot") != str(stage) or plan.get("receiptPath") != str(RECEIPT):
        fail("trust plan fixed paths changed")
    receipt_id = plan.get("receiptId")
    source_sha = plan.get("sourceSha")
    if not isinstance(receipt_id, str) or not receipt_id.isalnum() or len(receipt_id) > 64:
        fail("trust plan receipt ID is invalid")
    if not isinstance(source_sha, str) or len(source_sha) != 40 or any(char not in "0123456789abcdef" for char in source_sha):
        fail("trust plan source SHA is invalid")
    backup_root = pathlib.Path(plan.get("backupRoot", ""))
    if not backup_root.is_absolute() or backup_root.parent != BACKUP_PARENT or backup_root.name != receipt_id:
        fail("trust backup root is invalid")
    directory(backup_root)
    return plan, backup_root


def load_receipt(plan):
    regular(RECEIPT)
    with open(RECEIPT, "r", encoding="utf-8") as handle:
        receipt = json.load(handle)
    if (
        not isinstance(receipt, dict)
        or receipt.get("version") != 1
        or receipt.get("receiptId") != plan["receiptId"]
        or receipt.get("sourceSha") != plan["sourceSha"]
        or receipt.get("backupRoot") != plan["backupRoot"]
        or not isinstance(receipt.get("changed"), list)
    ):
        fail("trust installation receipt does not match runtime installation")
    return receipt


def generate_response_pair(stage):
    private_stage = stage / "response-private.pem"
    public_stage = stage / "response-public.pem"
    if RESPONSE_PRIVATE.exists():
        regular(RESPONSE_PRIVATE)
        shutil.copy2(RESPONSE_PRIVATE, private_stage, follow_symlinks=False)
    else:
        result = subprocess.run(
            ["/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private_stage)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            fail("response private key generation failed")
    os.chmod(private_stage, 0o600)
    result = subprocess.run(
        ["/usr/bin/openssl", "pkey", "-in", str(private_stage), "-pubout", "-out", str(public_stage)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        fail("response public key generation failed")
    os.chmod(public_stage, 0o644)
    return private_stage, public_stage


def main():
    if os.geteuid() != 0:
        fail("remote trust installer must run as root")
    if len(sys.argv) != 2:
        fail("remote trust installer requires one staged directory")
    stage = pathlib.Path(sys.argv[1])
    if not stage.is_absolute() or stage.parent != pathlib.Path("/tmp") or stage.is_symlink() or not stage.is_dir():
        fail("remote trust stage is invalid")
    runtime_gid = pwd.getpwnam("opshaven").pw_gid
    plan, backup_root = load_plan(stage)
    receipt = load_receipt(plan)
    journal = []
    changed = []
    try:
        for name, (destination, mode) in DESTINATIONS.items():
            install_changed(stage / name, destination, mode, backup_root, journal, changed)
        private_stage, public_stage = generate_response_pair(stage)
        install_changed(private_stage, RESPONSE_PRIVATE, 0o640, backup_root, journal, changed, 0, runtime_gid)
        install_changed(public_stage, RESPONSE_PUBLIC, 0o644, backup_root, journal, changed)
        receipt_changed = list(receipt["changed"])
        for item in changed:
            if item not in receipt_changed:
                receipt_changed.append(item)
        receipt["changed"] = receipt_changed
        receipt["trustInstalled"] = True
        atomic_json(receipt, RECEIPT)
        evidence = {}
        for key, destination in {
            "config": DESTINATIONS["remote-config.json"][0],
            "publicKey": DESTINATIONS["operator-public.pem"][0],
            "capability": DESTINATIONS["capability.json"][0],
            "declaration": DESTINATIONS["declaration.json"][0],
            "binding": DESTINATIONS["binding.json"][0],
            "responsePublic": RESPONSE_PUBLIC,
        }.items():
            evidence[key] = sha256_file(destination)
        print(json.dumps({"ok": True, "hashes": evidence, "responsePublic": str(RESPONSE_PUBLIC), "changed": changed}, sort_keys=True))
    except Exception:
        restore(journal)
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        sys.exit(1)
