#!/usr/bin/env python3
"""
Setup script for Python CLI tool
This defines console_scripts entry points indicating it's a CLI tool
"""

from setuptools import setup, find_packages

setup(
    name='test-python-cli',
    version='1.0.0',
    description='Sample Python CLI tool for testing XSS false positive detection',
    author='Test Author',
    author_email='test@example.com',
    packages=find_packages(),
    install_requires=[
        'click>=8.0.0',
        'colorama>=0.4.4',
    ],
    entry_points={
        'console_scripts': [
            'test-cli=cli_tool.main:cli',
            'test-runner=cli_tool.runner:run',
        ],
    },
    python_requires='>=3.7',
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)
