"""Setup shim for the argus-code-reviewer package.

Package metadata (name, version, dependencies) lives in pyproject.toml.
"""
from setuptools import find_packages, setup

setup(
    packages=find_packages(where=".", exclude=["tests", "tests.*"]),
    package_dir={"": "."},
)
