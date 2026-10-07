"""Setup shim for the argus-code-reviewer package.

Package metadata (name, version, dependencies) lives in pyproject.toml.
"""

from pathlib import Path
from shutil import copytree

from setuptools import find_packages, setup
from setuptools.command.build_py import build_py


class BuildWithResources(build_py):
    """Bundle authoritative source assets without maintaining duplicate copies."""

    def run(self):
        super().run()
        root = Path(__file__).resolve().parent
        destination = Path(self.build_lib) / "scripts" / "resources"
        for directory in ("profiles", "policy", "rules", "schemas", "templates"):
            copytree(root / directory, destination / directory, dirs_exist_ok=True)


setup(
    packages=find_packages(where=".", include=["scripts", "scripts.*"]),
    package_dir={"": "."},
    cmdclass={"build_py": BuildWithResources},
)
