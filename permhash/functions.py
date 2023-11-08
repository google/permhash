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
"""

import logging
from permhash.helpers import (
    check_type,
    calc_permhash,
    create_crx_permlist,
    create_crx_manifest_permlist,
    create_apk_manifest_permlist,
    create_apk_permlist,
)

APK_MIMETYPES = [
    "application/zip",
    "application/java-archive",
    "application/vnd.android.package-archive",
]
CRX_MANIFEST_MIMETYPES = ["text/plain", "application/json"]
CRX_MIMETYPES = ["application/x-chrome-extension", "application/zip"]
APK_MANIFEST_MIMETYPES = ["application/octet-stream"]


def permhash_crx(path):
    """
    Returns the permhash of a file at the designated path.
    The file at the designated path must be a CRX file.
    http://www.dre.vanderbilt.edu/~schmidt/android/android-4.0/external/chromium/chrome/common/extensions/docs/crx.html

    :param path: The targeted file
    :type path: string
    """
    if check_type(path, CRX_MIMETYPES):
        return calc_permhash(create_crx_permlist(path), path)
    logging.warning(
        "This file is not a type that is currently handled \
            (CRX, APK, CRX Manifest, or APK Manifest): (%s)",
        path,
    )
    return False


def permhash_crx_manifest(path):
    """
    Returns the permhash of a file at the designated path.
    The file at the designated path must be a chromium-based extension manifest.
    https://developer.chrome.com/docs/extensions/mv3/manifest/

    :param path: The targeted file
    :type path: string
    """
    if check_type(path, CRX_MANIFEST_MIMETYPES):
        return calc_permhash(create_crx_manifest_permlist(path), path)
    logging.warning(
        "This file is not a type that is currently handled \
(CRX, APK, CRX Manifest, or APK Manifest): (%s)",
        path,
    )
    return False


def permhash_apk_manifest(path):
    """
    Returns the permhash of a file at the designated path

    :param path: The targeted file
    :type path: string
    """
    if check_type(path, APK_MANIFEST_MIMETYPES):
        return calc_permhash(create_apk_manifest_permlist(path), path)
    logging.warning(
        "This file is not a type that is currently handled \
(CRX, APK, CRX Manifest, or APK Manifest): (%s)",
        path,
    )
    return False


def permhash_apk(path):
    """
    Returns the permhash of a file at the designated path

    :param path: The targeted file
    :type path: string
    """
    if check_type(path, APK_MIMETYPES):
        return calc_permhash(create_apk_permlist(path), path)
    logging.warning(
        "This file is not a type that is currently handled \
(CRX, APK, CRX Manifest, or APK Manifest): (%s)",
        path,
    )
    return False
