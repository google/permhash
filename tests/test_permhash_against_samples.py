"""
Copyright 2023 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

------------------------------------------------------------------------

Samples with no permissions:
    069ccbc9ee6fda32e0995937158790aadc9356313a0f8ea1564883714accd527
    563caca7686debdfada1d03d850fc935ca44cdb1b045bad8496a32c35b1950fb

Samples with no Manifest:
    b83ec60cbe38e60021389c8f1882ee5564bfe0f4ee2242fe7a7be3a5c7f8e1c3

Samples that are unable to be read:
    bdbeca07a0cd8a61fbba558c1af5dc5a04a545e8c7c6030100410a5e46ed6128

Legitimate samples:
    aa18e880de24b87cb976609a6ee55f306eae5c7919683b1fc4782daade846f04
    9a3160dcb6dc459daeeea94b0acfdec30c48dba040a712c9940489eebd734992
    08ade47bb7176bbbe8c1b5b4a0d30e845fc54dd2fd606ce78f64d2c7afd52511
    c400b87cd89724f00b443bfb8cbd14f0f05757348a730f39b14040b25b3a74ef
    
NOTE: Due to github policy, we are unable to keep the following samples in the repository:
    bdbeca07a0cd8a61fbba558c1af5dc5a04a545e8c7c6030100410a5e46ed6128
    b83ec60cbe38e60021389c8f1882ee5564bfe0f4ee2242fe7a7be3a5c7f8e1c3
    08ade47bb7176bbbe8c1b5b4a0d30e845fc54dd2fd606ce78f64d2c7afd52511

"""

import os
from permhash import functions


CWD = os.getcwd()


def test_crx_manifest_legitimate():
    """
    Tests the permhash calculation of a CRX manifest file.
    The desired result should be def81bd23e3754f4b9708c89e975f0e6af7d3d84e03e089226fda7e263f8fb53
    def81bd23e3754f4b9708c89e975f0e6af7d3d84e03e089226fda7e263f8fb53 is the hash of
    "activeTabidentityidentity.emailcontextMenusstoragetabsunlimitedStoragescripting"
    """
    assert (
        functions.permhash_crx_manifest(
            CWD
            + "/tests/test_files/c400b87cd89724f00b443bfb8cbd14f0f05757348a730f39b14040b25b3a74ef"
        )
        == "def81bd23e3754f4b9708c89e975f0e6af7d3d84e03e089226fda7e263f8fb53"
    )


def test_apk_legitimate():
    """
    Tests the permhash calculation of an APK file.
    The desired result should be 8b9dee6bffe598ad20c3d1abf82152b57776130d686d27e32fc34f765de52125
    """
    assert (
        functions.permhash_apk(
            CWD
            + "/tests/test_files/9a3160dcb6dc459daeeea94b0acfdec30c48dba040a712c9940489eebd734992"
        )
        == "8b9dee6bffe598ad20c3d1abf82152b57776130d686d27e32fc34f765de52125"
    )


def test_apk_manifest_legitimate():
    """
    Tests the permhash calculation of an APK manifest file.
    The desired result should be 8b9dee6bffe598ad20c3d1abf82152b57776130d686d27e32fc34f765de52125
    """
    assert (
        functions.permhash_apk_manifest(
            CWD
            + "/tests/test_files/aa18e880de24b87cb976609a6ee55f306eae5c7919683b1fc4782daade846f04"
        )
        == "8b9dee6bffe598ad20c3d1abf82152b57776130d686d27e32fc34f765de52125"
    )


def test_no_permissions():
    """
    Tests the permhash calculation of a sample with no permissions.
    The desired result should be False
    """
    assert (
        functions.permhash_crx_manifest(
            CWD
            + "/tests/test_files/069ccbc9ee6fda32e0995937158790aadc9356313a0f8ea1564883714accd527"
        )
        is False
    )
    assert (
        functions.permhash_apk(
            CWD
            + "/tests/test_files/563caca7686debdfada1d03d850fc935ca44cdb1b045bad8496a32c35b1950fb"
        )
        is False
    )


def test_broken_strings():
    """
    Tests the permhash calculation of a sample with a broken string,
    which would be incorrect formatting. The desired result should be False
    """
    assert (
        functions.permhash_crx_manifest(
            CWD
            + "/tests/test_files/114a0709d58da99b61a08c8a0fb4ae099831b633717110957be6f9ff04747c11"
        )
        is False
    )


def test_abnormal_characters_and_encodings():
    """
    Tests the permhash calculation of samples with abnormal encodings or characters.
    The desired result should be False
    """
    assert (
        functions.permhash_crx_manifest(
            CWD
            + "/tests/test_files/1b3e9577a90a6d6aae50b15ae8a837c05205de6f6c3b6b5e00dc97fb791ec4ba"
        )
        is False
    )
    assert (
        functions.permhash_crx_manifest(
            CWD
            + "/tests/test_files/09c801371536abc0dbadd7b0561ef837f227b410e9e273e035fa1b910c1aa088"
        )
        is False
    )
    assert (
        functions.permhash_crx_manifest(
            CWD
            + "/tests/test_files/171f68fb1c511ae3c7f2bec28ccff6b802102266c85cd64c540e083e888228c0"
        )
        is False
    )


def test_manifest_with_comments():
    """
    Tests the permhash calculation of samples with abnormal encodings or characters.
    The desired result should be False
    """
    assert (
        functions.permhash_crx_manifest(
            CWD
            + "/tests/test_files/eb6b894d0f8688a06970d19f3ff0f963fe7d5554cd190984be8b68d9296350d4"
        )
        == "c1794090365f03b81f1e6e9fa678788a43d2d3bac2d1d854e415f3c09fbcfe86"
    )


def test_manifest_that_is_stomped():
    """
    Tests the permhash calculation of samples with abnormal encodings or characters.
    The desired result should be False
    """
    assert (
        functions.permhash_crx_manifest(
            CWD
            + "/tests/test_files/17308c8b11d64cd0bd54eb576c5ee182b803c84e2ea7884065e39b4055d863e8"
        )
        is False
    )


def test_apk_nonaxml():
    """
    Tests the permhash calculation of samples with abnormal encodings or characters.
    The desired result should be False
    """
    assert (
        functions.permhash_crx_manifest(
            CWD
            + "/tests/test_files/12073711df9d41dd7ec838a799a3a0114bb1822a37427e353d464eb771ceec73"
        )
        is False
    )


# Due to the inability to keep these samples in github, these test
# functions are being moved into comments.
"""
def test_permhash_no_manifest():
    assert (
        functions.permhash_crx(
            CWD + "/tests/test_files/b83ec60cbe38e60021389c8f1882ee5564bfe0f4ee2242fe7a7be3a5c7f8e1c3"
        )
        is False
    )


def test_permhash_unreadable():
    assert (
        functions.permhash_crx(
            CWD + "/tests/test_files/bdbeca07a0cd8a61fbba558c1af5dc5a04a545e8c7c6030100410a5e46ed6128"
        )
        is False
    )
    
def test_permhash_crx():
    assert (
        functions.permhash_crx(
            CWD + "/tests/test_files/08ade47bb7176bbbe8c1b5b4a0d30e845fc54dd2fd606ce78f64d2c7afd52511"
        )
        == "def81bd23e3754f4b9708c89e975f0e6af7d3d84e03e089226fda7e263f8fb53"
    )
"""
