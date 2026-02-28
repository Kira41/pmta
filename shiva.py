#!/usr/bin/env python
from __future__ import print_function

import os
import runpy
import sys


def main():
    if sys.version_info[0] < 3:
        sys.stderr.write(
            "This application requires Python 3.\n"
            "Run it with: python3 shiva.py\n"
        )
        return 1

    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shiva_app.py")
    runpy.run_path(target, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
