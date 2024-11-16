#!/usr/bin/env python
try:
    from setuptools import setup ,find_packages
except ImportError:
    from distutils.core import setup

import os

version_path = os.path.join(os.path.dirname(__file__), "b_hunters/__version__.py")
version_info = {}
with open(version_path) as f:
    exec(f.read(), version_info)

setup(
    name="b_hunters",
    version=version_info["__version__"],
    description="**B-Hunters** is a bug bounty framework built on the Karton",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    namespace_packages=["b_hunters"],
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    url="https://github.com/B-Hunters/B-Hunters",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: BSD License",
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'b-hunters=b_hunters.cli:main',  
        ],},

)