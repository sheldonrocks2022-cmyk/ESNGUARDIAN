from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data" / "release_guard"
STATE_PATH = DATA_DIR / "startup_state.json"
LAST_GOOD = DATA_DIR / "last_good.zip"
MANIFEST = ROOT / "guardian_manifest.json"
SIGNATURE = ROOT / "guardian_manifest.sig"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release() -> tuple[bool, list[str]]:
    if not MANIFEST.exists():
        return True, []
    try:
        payload = MANIFEST.read_bytes()
        manifest: dict[str, Any] = json.loads(payload.decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        return False, [f"Could not read release manifest: {error}"]

    problems: list[str] = []
    for relative, expected in dict(manifest.get("files", {})).items():
        path = ROOT / relative
        if not path.is_file():
            problems.append(f"Missing release file: {relative}")
            continue
        actual = _sha256(path)
        if not hmac.compare_digest(actual, str(expected)):
            problems.append(f"Checksum mismatch: {relative}")

    key = os.getenv("GUARDIAN_RELEASE_HMAC_KEY", "").encode("utf-8")
    if key:
        if not SIGNATURE.exists():
            problems.append("Release signature is required but guardian_manifest.sig is missing")
        else:
            expected_sig = SIGNATURE.read_text(encoding="utf-8").strip()
            actual_sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_sig, actual_sig):
                problems.append("Release signature verification failed")

    return not problems, problems


def _state() -> dict[str, Any]:
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(payload: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp = STATE_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temp.replace(STATE_PATH)


def prepare_startup() -> bool:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    previous = _state()
    failures = int(previous.get("failures", 0) or 0)
    if previous.get("status") == "starting":
        failures += 1

    if failures >= 2 and LAST_GOOD.exists() and not previous.get("rollback_used", False):
        with zipfile.ZipFile(LAST_GOOD) as archive:
            archive.extractall(ROOT)
        _write_state({
            "status": "rollback_restored",
            "failures": 0,
            "rollback_used": True,
        })
        return True

    _write_state({
        "status": "starting",
        "failures": failures,
        "rollback_used": bool(previous.get("rollback_used", False)),
    })
    return False


def mark_healthy() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp_zip = LAST_GOOD.with_suffix(".tmp.zip")
    include = [ROOT / "bot.py", ROOT / "main.py", ROOT / "requirements.txt"]
    include.extend((ROOT / "esn_guardian").rglob("*.py"))
    with zipfile.ZipFile(temp_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in include:
            if path.is_file():
                archive.write(path, path.relative_to(ROOT))
    shutil.move(str(temp_zip), str(LAST_GOOD))
    _write_state({
        "status": "healthy",
        "failures": 0,
        "rollback_used": False,
    })
