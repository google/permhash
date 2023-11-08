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

from setuptools import find_packages, setup

setup(
    name="permhash",
    packages=find_packages(include=["permhash", "permhash.scripts"]),
    version="0.1.4",
    description="Permhash calculator",
    author="jaredscottwilson",
    license="Google",
    install_requires=[
        "androguard>=3.3.5",
        "python-magic>=0.4.27",
        "bs4>=0.0.1",
        "jstyleson>=0.0.2",
    ],
    setup_requires=["pytest-runner"],
    tests_require=["pytest==4.4.1"],
    test_suite="tests",
    entry_points={
        "console_scripts": [
            # command = package.module:function
            "permhash = permhash.scripts.cli:main",
        ],
    },
)
