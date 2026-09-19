# -*- coding: utf-8 -*-
"""Authorization gate — refuse to run without explicit permission."""

import os
import sys


class AuthorizationError(Exception):
    """Raised when the user has not confirmed authorization."""


def require_authorization(authorized_flag: bool = False) -> None:
    """Block execution unless the user has passed --authorized or set the env var.

    The env var `VULNSCAN_AUTHORIZED=1` is accepted as an alternative to the CLI flag
    so that automation (e.g. CI) can pre-approve runs in trusted environments.
    """
    if authorized_flag or os.environ.get("VULNSCAN_AUTHORIZED") == "1":
        return

    print(
        "═" * 68,
        file=sys.stderr,
    )
    print(
        "  ⚠  AUTHORIZATION REQUIRED",
        file=sys.stderr,
    )
    print(
        "  This tool is for authorized security testing only.",
        file=sys.stderr,
    )
    print(
        "  Unauthorized scanning is illegal and violates responsible disclosure.",
        file=sys.stderr,
    )
    print(
        "  Use --authorized to confirm you own/have permission for the target,",
        file=sys.stderr,
    )
    print(
        "  or set VULNSCAN_AUTHORIZED=1 in your environment.",
        file=sys.stderr,
    )
    print(
        "═" * 68,
        file=sys.stderr,
    )
    raise AuthorizationError("Scan refused: no authorization provided")
