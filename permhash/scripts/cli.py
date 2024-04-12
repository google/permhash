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
import argparse
from permhash.functions import (
    permhash_apk_manifest,
    permhash_apk,
    permhash_crx,
    permhash_crx_manifest,
    permhash_ipa,
    permhash_macho,
)
from permhash.helpers import is_dir


def main():
    """
    Intended to help handle argparsing
    and CLI function calling
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
        help="The filetype of the file you'd like to compute permhash for.",
    )
    args = parser.parse_args()
    files = is_dir(args.path)
    if files:
        for file in files:
            if args.type == "crx":
                print(permhash_crx(args.path+file))
            elif args.type == "crx_manifest":
                print(permhash_crx_manifest(args.path+file))
            elif args.type == "apk":
                print(permhash_apk(args.path+file))
            elif args.type == "apk_manifest":
                print(permhash_apk_manifest(args.path+file))
            elif args.type == "ipa":
                print(permhash_ipa(args.path+file))
            elif args.type == "macho":
                print(permhash_macho(args.path+file))
            else:
                logging.warning(
                    "This file is not a type that is currently handled (CRX, APK, CRX Manifest, APK Manifest, IPA, or Mach-O): (%s)",
                    args.path,
                )
    if args.type == "crx":
        print(permhash_crx(args.path))
    elif args.type == "crx_manifest":
        print(permhash_crx_manifest(args.path))
    elif args.type == "apk":
        print(permhash_apk(args.path))
    elif args.type == "apk_manifest":
        print(permhash_apk_manifest(args.path))
    elif args.type == "ipa":
        print(permhash_ipa(args.path))
    elif args.type == "macho":
        print(permhash_macho(args.path))
    else:
        logging.warning(
            "This file is not a type that is currently handled (CRX, APK, CRX Manifest, APK Manifest, IPA, or Mach-O): (%s)",
            args.path,
        )


if __name__ == " __main__":
    main()
