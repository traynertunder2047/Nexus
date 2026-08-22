"""CLI entry point: python -m modules.metadata.locus <image_path>"""

import json
import sys

from .pipeline import run


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m modules.metadata.locus <image_path>")
        sys.exit(1)
    print(json.dumps(run(sys.argv[1]), indent=1))


if __name__ == "__main__":
    main()