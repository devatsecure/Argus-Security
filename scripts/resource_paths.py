"""Locate built-in assets in either a source checkout or an installed wheel."""

from pathlib import Path


def resource_root() -> Path:
    module_dir = Path(__file__).resolve().parent
    bundled = module_dir / "resources"
    if bundled.is_dir():
        return bundled
    return module_dir.parent
