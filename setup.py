#!/usr/bin/env python
import os

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

version_path = os.path.join(os.path.dirname(__file__), "b_hunters/__version__.py")
version_info = {}
with open(version_path) as f:
    exec(f.read(), version_info)

here = os.path.dirname(os.path.abspath(__file__))


def _read(name):
    path = os.path.join(here, name)
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _requirements(name):
    """Read a requirements file, ignoring comments and blank lines."""
    lines = []
    for raw in _read(name).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


core_requirements = _requirements("requirements.txt")
platform_requirements = [
    requirement
    for requirement in core_requirements
    if not requirement.startswith(
        ("karton-core", "pymongo", "tldextract", "requests", "colorama", "cryptography")
    )
] + [
    # The secret box encrypts the stored credentials with AES-GCM.  The
    # pin is repeated here so that the platform extra carries it even
    # when the requirements file is reorganised.
    "cryptography>=42,<47",
    # The scheduler parses the cron expressions of the schedules.
    "croniter>=2,<7",
]

setup(
    name="b_hunters",
    version=version_info["__version__"],
    description=(
        "**B-Hunters** is a bug bounty and application security platform built on the "
        "Karton framework, with an authenticated API, an AI agent runtime and a "
        "vulnerable application benchmark suite."
    ),
    long_description=_read("README.md"),
    long_description_content_type="text/markdown",
    packages=find_packages(include=["b_hunters", "b_hunters.*"]),
    package_data={
        "b_hunters": [
            "web/*.html",
            "web/*.js",
            "web/*.css",
            "web/*.svg",
            "web/js/*.js",
            "web/js/views/*.js",
        ]
    },
    include_package_data=False,
    install_requires=core_requirements,
    extras_require={
        "platform": platform_requirements,
        "dev": [
            "pytest>=8.0",
            "pytest-asyncio>=0.23",
            "ruff>=0.5",
            "mypy>=1.10",
            "respx>=0.21",
        ],
    },
    url="https://github.com/B-Hunters/B-Hunters",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: BSD License",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "b-hunters=b_hunters.cli:main",
        ],
    },
)
