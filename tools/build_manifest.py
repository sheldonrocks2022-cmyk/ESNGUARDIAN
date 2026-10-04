from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    manifest_path = root / "guardian_manifest.json"
    signature_path = root / "guardian_manifest.sig"

    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in {"guardian_manifest.json", "guardian_manifest.sig"}:
            continue
        if relative.startswith("data/"):
            continue
        files[relative] = sha256(path)

    payload = json.dumps(
        {
            "format": 1,
            "guardian": "ESN Guardian",
            "release": "v7 MAX",
            "files": files,
        },
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    manifest_path.write_bytes(payload)

    key = os.getenv("GUARDIAN_RELEASE_HMAC_KEY", "").encode("utf-8")
    if key:
        signature_path.write_text(
            hmac.new(key, payload, hashlib.sha256).hexdigest() + "\n",
            encoding="utf-8",
        )
    elif signature_path.exists():
        signature_path.unlink()


if __name__ == "__main__":
    main()
