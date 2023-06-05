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
    526f2b6018785d9be4a885e789c94048.json

Samples with no Manifest:
    b1af73d36a3711cf65911dd7decc32d4.crx

Samples that are unable to be read:
    20992728e56336d1620fabfb86f5f75e.crx

Legitimate samples:
    AndroidManifest.xml
    com.google.android.keep.apk
    lpcaedmchfhocbbapmcbpinfpgnhiddi.crx
    manifest.json
    
NOTE: Due to github policy, we are unable to keep the following samples in the repository:
20992728e56336d1620fabfb86f5f75e.crx
b1af73d36a3711cf65911dd7decc32d4.crx
lpcaedmchfhocbbapmcbpinfpgnhiddi.crx

"""

import os
from permhash import functions


CWD = os.getcwd()

def test_permhash_crx_manifest():
    """
    Tests the permhash calculation of a CRX manifest file.
    The desired result should be e1d9f99354d29badeb319a515321668d
    e1d9f99354d29badeb319a515321668d is the hash of
    "activeTabidentityidentity.emailcontextMenusstoragetabsunlimitedStoragescripting"
    """
    assert (
        functions.permhash_crx_manifest(CWD + "/tests/test_files/manifest.json")
        == "def81bd23e3754f4b9708c89e975f0e6af7d3d84e03e089226fda7e263f8fb53"
    )


def test_permhash_apk():
    """
    Tests the permhash calculation of an APK file.
    The desired result should be 16e966c970778a207f0ac2e88adb4ab8
    """
    assert (
        functions.permhash_apk(CWD + "/tests/test_files/com.google.android.keep.apk")
        == "8b9dee6bffe598ad20c3d1abf82152b57776130d686d27e32fc34f765de52125"
    )


def test_permhash_apk_manifest():
    """
    Tests the permhash calculation of an APK manifest file.
    The desired result should be 16e966c970778a207f0ac2e88adb4ab8
    """
    assert (
        functions.permhash_apk_manifest(CWD + "/tests/test_files/AndroidManifest.xml")
        == "8b9dee6bffe598ad20c3d1abf82152b57776130d686d27e32fc34f765de52125"
    )


def test_permhash_no_permissions():
    """
    Tests the permhash calculation of a sample with no permissions.
    The desired result should be False
    """
    assert (
        functions.permhash_crx_manifest(
            CWD + "/tests/test_files/526f2b6018785d9be4a885e789c94048.json"
        )
        is False
    )



# Due to the inability to keep these samples in github, these test
# functions are being moved into comments.

"""
def test_permhash_no_manifest():
    assert (
        functions.permhash_crx(
            CWD + "/tests/test_files/b1af73d36a3711cf65911dd7decc32d4.crx"
        )
        is False
    )


def test_permhash_unreadable():
    assert (
        functions.permhash_crx(
            CWD + "/tests/test_files/20992728e56336d1620fabfb86f5f75e.crx"
        )
        is False
    )
    
def test_permhash_crx():
    assert (
        functions.permhash_crx(
            CWD + "/tests/test_files/lpcaedmchfhocbbapmcbpinfpgnhiddi.crx"
        )
        == "def81bd23e3754f4b9708c89e975f0e6af7d3d84e03e089226fda7e263f8fb53"
    )
"""
