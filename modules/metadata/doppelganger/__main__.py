"""CLI entry point:
python -m modules.metadata.doppelganger <image_path> [handle1 handle2 ...]"""

import json
import sys

from .pipeline import run


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m modules.metadata.doppelganger <image_path> [handle1 handle2 ...]")
        sys.exit(1)
    print(json.dumps(run(sys.argv[1], handles=sys.argv[2:]), indent=1))


if __name__ == "__main__":
    main()