#!/usr/bin/env python3
"""GODRECON main entry point.

Usage::

    python main.py scan --target example.com
    python main.py scan --target example.com --full --format html -o report.html
    python main.py version
    python main.py config
"""

from godrecon.cli import main

if __name__ == "__main__":
    main()
