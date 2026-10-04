from __future__ import annotations

import os
import sys

from esn_guardian.release_guard import prepare_startup, verify_release


if prepare_startup():
    os.execv(sys.executable, [sys.executable, __file__])

ok, problems = verify_release()
if not ok and os.getenv("GUARDIAN_ALLOW_INTEGRITY_FAILURE", "").strip() != "1":
    raise SystemExit(
        "Guardian release integrity verification failed:\n- " + "\n- ".join(problems)
    )

from esn_guardian.main import main


if __name__ == "__main__":
    main()
