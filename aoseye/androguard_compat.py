"""Compatibility fixes for Androguard's bundled text resources."""

from functools import partial
from io import open as io_open


def configure_resource_encoding() -> None:
    """Read Androguard 4.x permission JSON as UTF-8 on every platform."""
    from androguard.core import api_specific_resources

    # These loaders omit encoding when opening their bundled UTF-8 JSON.
    # Override only this module's text-file opener, not builtins.open or
    # the process locale. Imported loader aliases use these same globals.
    api_specific_resources.open = partial(io_open, encoding="utf-8")
