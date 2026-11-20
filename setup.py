"""
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from pathlib import Path
from setuptools import find_packages, setup

LONG_DESCRIPTION = (Path(__file__).parent / "README.md").read_text(
    encoding="utf-8"
)

setup(
    name="permhash",
    packages=find_packages(include=["permhash", "permhash.scripts"]),
    version="1.0.2",
    description="Permhash calculator",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/google/permhash",
    author="jaredscottwilson",
    license="Apache-2.0",
    python_requires=">=3.9",
    package_data={"permhash": ["detect.yar"]},
    install_requires=[
        "androguard>=4.1.4",
        "beautifulsoup4>=4.12.3",
        "jstyleson>=0.0.2",
        "lxml>=5.3.0",
        "python-magic>=0.4.27",
        "yara-python>=4.5.0",
    ],
    entry_points={
        "console_scripts": [
            # command = package.module:function
            "permhash = permhash.scripts.cli:main",
        ],
    },
)
