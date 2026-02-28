#!/usr/bin/env python
from __future__ import print_function

import os
import runpy
import sys
import importlib


def _check_runtime_requirements():
    """Return list of missing package names required by shiva_app.py."""
    required_modules = ["flask"]
    # dataclasses is built-in on Python 3.7+, backport package on 3.6.
    if sys.version_info < (3, 7):
        required_modules.append("dataclasses")

    missing = []
    for module_name in required_modules:
        try:
            importlib.import_module(module_name)
        except Exception:
            missing.append(module_name)
    return missing


def main():
    if sys.version_info[0] < 3:
        sys.stderr.write(
            "This application requires Python 3.\n"
            "Run it with: python3 shiva.py\n"
        )
        return 1

    missing = _check_runtime_requirements()
    if missing:
        sys.stderr.write(
            "Missing required Python module(s): {}\n".format(
                ", ".join(sorted(missing))
            )
        )
        sys.stderr.write(
            "Install dependencies with:\n"
            "  python3 -m pip install -r requirements.txt\n"
        )
        return 1

    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shiva_app.py")
    runpy.run_path(target, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
