"""Setup script for argus-code-reviewer package."""
from setuptools import find_packages, setup

setup(
    name="argus-code-reviewer",
    version="1.0.15",
    packages=find_packages(where=".", exclude=["tests", "tests.*"]),
    package_dir={"": "."},
)
