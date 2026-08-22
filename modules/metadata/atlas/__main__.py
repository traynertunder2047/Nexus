"""CLI entry point: python -m modules.metadata.atlas "text to analyze..."

Multiple arguments are joined into a single text string."""

import json
import sys

from .pipeline import run


def main() -> None:
    if len(sys.argv) < 2:
        print('Usage: python -m modules.metadata.atlas "text to analyze..."')
        sys.exit(1)
    print(json.dumps(run(" ".join(sys.argv[1:])), indent=1))


if __name__ == "__main__":
    main()