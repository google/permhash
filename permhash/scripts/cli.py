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

import argparse
import logging
import os

from permhash.functions import (
    permhash_apk,
    permhash_apk_manifest,
    permhash_crx,
    permhash_crx_manifest,
    permhash_ipa,
    permhash_macho,
)
from permhash.helpers import is_dir


def main():
    """
    Intended to help handle argparsing
    and CLI function calling.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p",
        "--path",
        required=True,
        type=str,
        action="store",
        help="Full path to file to calculate permhash from.",
    )
    parser.add_argument(
        "-t",
        "--type",
        required=True,
        type=str.lower,
        choices=["apk", "apk_manifest", "crx", "crx_manifest", "ipa", "macho"],
        action="store",
        help="The type of permhash you'd like to compute (crx, crx_manifest, apk, apk_manifest, ipa, macho)",
    )
    args = parser.parse_args()
    handlers = {
        "crx": permhash_crx,
        "crx_manifest": permhash_crx_manifest,
        "apk": permhash_apk,
        "apk_manifest": permhash_apk_manifest,
        "ipa": permhash_ipa,
        "macho": permhash_macho,
    }
    handler = handlers.get(args.type)
    if not handler:
        logging.warning(
            "This file is not a type that is currently handled "
            "(CRX, APK, CRX Manifest, APK Manifest, IPA, or Mach-O): (%s)",
            args.path,
        )
        return

    files = is_dir(args.path)
    if files:
        for file in files:
            print(handler(os.path.join(args.path, file)))
    else:
        print(handler(args.path))


if __name__ == "__main__":
    main()
