#!/usr/bin/env python3
import hashlib
import json
import os
import pwd
import grp
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ACCOUNT = "opshaven"
RUNTIME_ROOT = Path("/usr/lib/opshaven")
CONFIG_PATH = Path("/etc/opshaven/config.json")
WRAPPER_PATH = Path("/usr/local/bin/opshaven-readonly-force-command")
STATE_DIRECTORY = Path("/var/lib/opshaven")
RECEIPT_PATH = STATE_DIRECTORY / "setup-receipt.json"
AUTHORIZED_KEYS = Path("/home/opshaven/.ssh/authorized_keys")
ALLOWED_ROOTS = (Path("/etc/opshaven"), Path("/usr/lib/opshaven"), Path("/usr/local/bin"), Path("/var/lib/opshaven"), Path("/home/opshaven"))
PRIVILEGED_GROUPS = {"sudo", "wheel", "docker", "lxd"}


def fail(message):
    raise RuntimeError(message)


def sha256_file(file_path):
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative(value):
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        fail("Runtime manifest contains an unsafe relative path.")
    if any(part in ("", ".") for part in candidate.parts):
        fail("Runtime manifest contains a non-normalized path.")
    return candidate


def require_regular(file_path, maximum_bytes=16 * 1024 * 1024):
    info = os.lstat(file_path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > maximum_bytes:
        fail(f"Unsafe staged file: {file_path}")


def ensure_exact_plan(plan, stage_root):
    expected = {
        "version",
        "receiptId",
        "sourceSha",
        "nodePath",
        "stageRoot",
        "account",
        "runtimeRoot",
        "configPath",
        "wrapperPath",
        "stateDirectory",
        "receiptPath",
        "runtimeManifest",
        "remoteConfig",
        "wrapper",
        "authorizedKeys",
    }
    if set(plan.keys()) != expected or plan.get("version") != 1:
        fail("Installer plan schema is incompatible.")
    fixed = {
        "stageRoot": str(stage_root),
        "account": ACCOUNT,
        "runtimeRoot": str(RUNTIME_ROOT),
        "configPath": str(CONFIG_PATH),
        "wrapperPath": str(WRAPPER_PATH),
        "stateDirectory": str(STATE_DIRECTORY),
        "receiptPath": str(RECEIPT_PATH),
    }
    for key, value in fixed.items():
        if plan.get(key) != value:
            fail(f"Installer plan changed fixed field {key}.")
    if not isinstance(plan.get("receiptId"), str) or not plan["receiptId"].isalnum() or len(plan["receiptId"]) > 64:
        fail("Installer receipt ID is invalid.")
    if not isinstance(plan.get("sourceSha"), str) or len(plan["sourceSha"]) != 40 or any(char not in "0123456789abcdef" for char in plan["sourceSha"]):
        fail("Installer source SHA is invalid.")
    node_path = Path(plan.get("nodePath", ""))
    if not node_path.is_absolute() or not node_path.is_file() or not os.access(node_path, os.X_OK) or os.path.realpath(node_path) != str(node_path):
        fail("Resolved Node executable is unavailable or changed.")
    for key in ("runtimeManifest", "remoteConfig", "wrapper", "authorizedKeys"):
        item = safe_relative(plan.get(key, ""))
        require_regular(stage_root / item)


def run_checked(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False)
    if result.returncode != 0:
        fail(f"Required system command failed: {args[0]}")


def account_ids():
    try:
        entry = pwd.getpwnam(ACCOUNT)
    except KeyError:
        useradd = "/usr/sbin/useradd"
        if not os.path.isfile(useradd):
            fail("useradd is unavailable.")
        run_checked([useradd, "--system", "--create-home", "--home-dir", f"/home/{ACCOUNT}", "--shell", "/bin/bash", "--user-group", ACCOUNT])
        entry = pwd.getpwnam(ACCOUNT)
    usermod = "/usr/sbin/usermod"
    if os.path.isfile(usermod):
        run_checked([usermod, "--lock", ACCOUNT])
    memberships = {group.gr_name for group in grp.getgrall() if ACCOUNT in group.gr_mem}
    primary = grp.getgrgid(entry.pw_gid).gr_name
    memberships.add(primary)
    if memberships & PRIVILEGED_GROUPS:
        fail("Restricted account belongs to a privileged group.")
    if Path("/etc/sudoers.d/opshaven").exists():
        fail("Read-only account has an unexpected sudoers rule.")
    return entry.pw_uid, entry.pw_gid


def ensure_directory(directory, mode, uid, gid):
    current = Path("/")
    for part in directory.parts[1:]:
        current = current / part
        if current.exists() and current.is_symlink():
            fail(f"Refusing symlinked installation directory: {current}")
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        fail(f"Installation directory is unsafe: {directory}")
    os.chmod(directory, mode)
    os.chown(directory, uid, gid)


def fsync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_copy(source, destination, mode, uid, gid):
    require_regular(source)
    ensure_directory(destination.parent, 0o755, 0, 0)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.opshaven-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as output, open(source, "rb") as input_handle:
            shutil.copyfileobj(input_handle, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, destination)
        fsync_directory(destination.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def backup_path(destination, backup_root):
    relative = Path(str(destination).lstrip("/"))
    return backup_root / relative


def backup_existing(destination, backup_root, backups):
    if not destination.exists():
        return
    if destination.is_symlink():
        fail(f"Refusing to replace symlinked path: {destination}")
    backup = backup_path(destination, backup_root)
    backup.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_dir():
        shutil.copytree(destination, backup, symlinks=False)
    elif destination.is_file():
        shutil.copy2(destination, backup)
    else:
        fail(f"Refusing unsupported existing path: {destination}")
    backups.append((destination, backup))


def restore_backups(backups):
    for destination, backup in reversed(backups):
        if destination.exists():
            if destination.is_dir():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(backup, destination)


def load_manifest(stage_root, relative_path):
    manifest_path = stage_root / safe_relative(relative_path)
    require_regular(manifest_path, 2 * 1024 * 1024)
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict) or set(manifest.keys()) != {"version", "files", "treeSha256"} or manifest.get("version") != 1:
        fail("Runtime manifest schema is invalid.")
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > 4096:
        fail("Runtime manifest file list is invalid.")
    normalized = []
    for item in files:
        if not isinstance(item, dict) or set(item.keys()) != {"path", "sha256", "executable"}:
            fail("Runtime manifest entry is invalid.")
        relative = safe_relative(item.get("path", ""))
        digest = item.get("sha256", "")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            fail("Runtime manifest hash is invalid.")
        if not isinstance(item.get("executable"), bool):
            fail("Runtime manifest executable flag is invalid.")
        normalized.append((relative, digest, item["executable"]))
    canonical = json.dumps([{"executable": executable, "path": str(relative), "sha256": digest} for relative, digest, executable in normalized], separators=(",", ":"), sort_keys=True).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != manifest.get("treeSha256"):
        fail("Runtime manifest tree hash is invalid.")
    return manifest, normalized


def install_runtime(stage_root, manifest_relative, receipt_id, backup_root, backups):
    manifest, entries = load_manifest(stage_root, manifest_relative)
    source_root = stage_root / "runtime"
    if source_root.is_symlink() or not source_root.is_dir():
        fail("Staged runtime root is invalid.")
    for relative, digest, _ in entries:
        source = source_root / relative
        require_regular(source)
        if sha256_file(source) != digest:
            fail(f"Runtime file hash mismatch: {relative}")
    installed_manifest = STATE_DIRECTORY / "runtime-manifest.json"
    if RUNTIME_ROOT.is_dir() and installed_manifest.is_file():
        try:
            with open(installed_manifest, "r", encoding="utf-8") as handle:
                current = json.load(handle)
            if current.get("treeSha256") == manifest.get("treeSha256"):
                return False, manifest["treeSha256"]
        except (OSError, ValueError, AttributeError):
            pass
    temporary_root = RUNTIME_ROOT.parent / f".{RUNTIME_ROOT.name}.next-{receipt_id}"
    if temporary_root.exists():
        shutil.rmtree(temporary_root)
    temporary_root.mkdir(parents=True, mode=0o755)
    try:
        for relative, digest, executable in entries:
            source = source_root / relative
            destination = temporary_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            os.chmod(destination, 0o755 if executable else 0o644)
            os.chown(destination, 0, 0)
            if sha256_file(destination) != digest:
                fail(f"Installed runtime verification failed: {relative}")
        for root, directories, _ in os.walk(temporary_root):
            os.chmod(root, 0o755)
            os.chown(root, 0, 0)
            for directory in directories:
                os.chmod(Path(root) / directory, 0o755)
                os.chown(Path(root) / directory, 0, 0)
        backup_existing(RUNTIME_ROOT, backup_root, backups)
        if RUNTIME_ROOT.exists():
            shutil.rmtree(RUNTIME_ROOT)
        os.replace(temporary_root, RUNTIME_ROOT)
        fsync_directory(RUNTIME_ROOT.parent)
        atomic_json(manifest, installed_manifest, 0o600, 0, 0)
        return True, manifest["treeSha256"]
    finally:
        if temporary_root.exists():
            shutil.rmtree(temporary_root)


def atomic_text(text, destination, mode, uid, gid):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.opshaven-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, destination)
        fsync_directory(destination.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(value, destination, mode, uid, gid):
    atomic_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", destination, mode, uid, gid)


def install_file(stage_root, relative, destination, mode, uid, gid, backup_root, backups):
    source = stage_root / safe_relative(relative)
    require_regular(source)
    if destination.exists() and destination.is_file() and sha256_file(destination) == sha256_file(source):
        os.chmod(destination, mode)
        os.chown(destination, uid, gid)
        return False
    backup_existing(destination, backup_root, backups)
    atomic_copy(source, destination, mode, uid, gid)
    return True


def main():
    if os.geteuid() != 0:
        fail("Remote installer must run as root.")
    if len(sys.argv) != 2:
        fail("Remote installer requires one staged directory.")
    stage_root = Path(sys.argv[1])
    if not stage_root.is_absolute() or stage_root.parent != Path("/tmp") or stage_root.is_symlink() or not stage_root.is_dir():
        fail("Remote installer stage path is invalid.")
    plan_path = stage_root / "plan.json"
    require_regular(plan_path, 1024 * 1024)
    with open(plan_path, "r", encoding="utf-8") as handle:
        plan = json.load(handle)
    ensure_exact_plan(plan, stage_root)
    uid, gid = account_ids()
    ensure_directory(Path("/etc/opshaven"), 0o755, 0, 0)
    ensure_directory(STATE_DIRECTORY, 0o700, uid, gid)
    ensure_directory(STATE_DIRECTORY / "remote-used", 0o700, uid, gid)
    ensure_directory(AUTHORIZED_KEYS.parent, 0o700, uid, gid)
    backup_root = STATE_DIRECTORY / "backups" / plan["receiptId"]
    ensure_directory(backup_root, 0o700, 0, 0)
    backups = []
    changed = []
    try:
        runtime_changed, runtime_hash = install_runtime(stage_root, plan["runtimeManifest"], plan["receiptId"], backup_root, backups)
        if runtime_changed:
            changed.append(str(RUNTIME_ROOT))
        for relative, destination, mode, owner_uid, owner_gid in (
            (plan["remoteConfig"], CONFIG_PATH, 0o644, 0, 0),
            (plan["wrapper"], WRAPPER_PATH, 0o755, 0, 0),
            (plan["authorizedKeys"], AUTHORIZED_KEYS, 0o600, uid, gid),
        ):
            if install_file(stage_root, relative, destination, mode, owner_uid, owner_gid, backup_root, backups):
                changed.append(str(destination))
        dispatcher = RUNTIME_ROOT / "src/remote/read-only-dispatcher.js"
        require_regular(dispatcher)
        os.chmod(dispatcher, 0o755)
        receipt = {
            "version": 1,
            "receiptId": plan["receiptId"],
            "sourceSha": plan["sourceSha"],
            "nodePath": plan["nodePath"],
            "runtimeTreeSha256": runtime_hash,
            "installedAt": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z"),
            "certified": False,
            "changed": changed,
            "backupRoot": str(backup_root),
        }
        atomic_json(receipt, RECEIPT_PATH, 0o600, 0, 0)
        print(json.dumps({"ok": True, "changed": changed, "runtimeTreeSha256": runtime_hash, "backupRoot": str(backup_root)}, sort_keys=True))
    except Exception:
        restore_backups(backups)
        raise
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        sys.exit(1)
