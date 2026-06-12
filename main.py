#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import io

def _setup_utf8_io():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

_setup_utf8_io()

from datamask.cli import cli

if __name__ == "__main__":
    cli()
