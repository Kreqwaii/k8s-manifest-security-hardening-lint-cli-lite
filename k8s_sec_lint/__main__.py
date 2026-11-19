"""Entry point for `python -m k8s_sec_lint`."""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
