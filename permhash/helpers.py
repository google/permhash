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

import hashlib
import os
import json
from json import JSONDecodeError
import logging
from zipfile import ZipFile, BadZipfile
from xml.dom import minidom
from androguard.core.bytecodes import axml
from bs4 import BeautifulSoup
import magic

APK_MIMETYPES = ["application/zip", "application/java-archive"]
CRX_MANIFEST_MIMETYPES = ["text/plain", "application/json"]
CRX_MIMETYPES = ["application/x-chrome-extension", "application/zip"]
APK_MANIFEST_MIMETYPES = ["application/octet-stream"]


def calc_md5(path):
    """
    Return the md5 of a file at a given path.

    :param path: The file to calc the md5 of.
    :type path: string
    """
    if is_file(path):
        md5_hash = hashlib.md5()
        with open(path, "rb") as inputfile:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: inputfile.read(4096), b""):
                md5_hash.update(byte_block)
            return md5_hash.hexdigest()
    else:
        return False


def is_file(path):
    """
    Checks to see if the file exists and is non-zero in size.

    :param path: The file to check.
    :type path: string
    """
    if os.path.exists(path):
        return bool(os.stat(path).st_size != 0)
    logging.warning(
        "This does not exist: (%s)",
        path,
    )
    return False


def check_type(path, mime):
    """
    Checks to see if mime type of the file at the provided
    path is the same as one passed in variable list mime

    :param path: The file to check.
    :type path: string
    :param mime: Potential desired mime types in a list.
    :type mime: list
    """
    if is_file(path):
        return bool(magic.from_file(path, mime=True) in mime)
    return False


def parse_crx_manifest(manifest_json):
    """
    Returns the permissions from a CRX manifest json dict

    :param manifest_json: the JSON manifest file text
    :type path: dict
    """
    if "permissions" in manifest_json:
        newpermlist = []
        currentpermlist = manifest_json["permissions"]
        if all(isinstance(item, str) for item in currentpermlist):
            # The permission list is all strings, we can just join that together.
            # No need to handle dicts.
            return currentpermlist
        for element in currentpermlist:
            if isinstance(element, str):
                # Take action to add string to the list
                newpermlist.append(element)
            elif isinstance(element, dict):
                # Logic to handle dictionary values
                values = list(element.values())[0]
                newpermkeys = ""
                newpermvalues = ""
                if all(isinstance(item, str) for item in values):
                    # The sub-dictionary has all string values
                    newpermkeys = list(element.keys())
                    newpermvalues = list(element.values())[0]
                    for subvalue in newpermvalues:
                        newpermlist.append(str(newpermkeys[0] + "." + str(subvalue)))
                else:
                    # There is a dictionary within the dictonary
                    # Example:
                    # {'usbDevices': [
                    #                   {'vendorId': 1155, 'productId': 57105},
                    #                   {'vendorId': 10473, 'productId': 393}
                    #               ]
                    # }
                    newpermkeys = list(element.keys())[0]
                    newpermvalues = list(element.values())[0]
                    for perm in newpermvalues:
                        embeddedpermkeys = list(perm.keys())[0]
                        embeddedpermvalues = list(perm.values())[0]
                        newpermlist.append(
                            newpermkeys
                            + "."
                            + str(embeddedpermkeys)
                            + "."
                            + str(embeddedpermvalues)
                        )
        return newpermlist
    return False


def calc_permhash(perm_list, path):
    """
    Calculates and returns the permhash from the list of permissions.

    :param perm_list: The list of string permissions
    :type perm_list: list
    """
    if perm_list is not False:
        if len(perm_list) == 0:
            logging.warning("This file has no permissions: %s", path)
            return False
        permstr = "".join(perm_list)
        return hashlib.sha256(permstr.encode("utf-8")).hexdigest()
    return False


def create_crx_permlist(path):
    """
    Creates and returns the list of permissions that will be used to create the permhash.

    :param path: The path to the file where the permissions need to be retrieved
    :type perm_list: string
    """
    # Ensure the file exists, is non-zero in size, and is a mimetype that a CRX should be
    if check_type(path, CRX_MIMETYPES):
        try:
            with ZipFile(path, mode="r") as crx_archive:
                manifest_present = False
                for entry in crx_archive.namelist():
                    if (entry.endswith("/manifest.json")) or (entry == "manifest.json"):
                        manifest_present = True
                        manifest_text = crx_archive.read(entry).decode(encoding="utf-8")
                if not manifest_present:
                    logging.warning("This CRX file has no Manifest: %s.", path)
                    return False
        except (BadZipfile, OSError):
            logging.warning(
                "This CRX file is corrupt and unable to be unzipped: %s.", path
            )
            return False
        except UnicodeDecodeError:
            logging.warning(
                "This Manifest has unrecgonizable and abnormal unicode issues: %s.",
                path,
            )
            return False
        try:
            manifest_json = json.loads(manifest_text)
        except JSONDecodeError:
            try:
                manifest_json = json.loads(manifest_text.encode().decode("utf-8-sig"))
            except JSONDecodeError:
                logging.warning(
                    "This Manifest file is abnormal and unable to be read: %s.", path
                )
                return False
        perm_list = parse_crx_manifest(manifest_json)
        return perm_list
    return False


def create_crx_manifest_permlist(path):
    """
    Creates and returns the list of permissions that will be used to create the permhash.

    :param path: The path to the file where the permissions need to be retrieved
    :type perm_list: string
    """
    # Ensure the file exists, is non-zero in size, and is a mimetype that a CRX should be
    if check_type(path, CRX_MANIFEST_MIMETYPES):
        with open(path, encoding="utf-8") as manifest:
            try:
                manifest_json = json.load(manifest)
            except OSError:
                logging.warning("Failure to load JSON from the manifest at %s", path)
                return False
            perm_list = parse_crx_manifest(manifest_json)
            return perm_list
    return False


def create_apk_manifest_permlist(path):
    """
    Creates and returns the list of permissions that will be used to create the permhash.

    :param path: The path to the file where the permissions need to be retrieved
    :type perm_list: string
    """
    with open(path, "rb") as manifest:
        try:
            manifest_data = axml.AXMLPrinter(manifest.read())
        except OSError:
            logging.warning("Failure to parse XML from the manifest at %s", path)
            return False
        if not manifest_data.is_valid():
            logging.warning(
                "This manifest does not appear to be an AXML file: %s.", path
            )
            return False
        try:
            initial_buff = manifest_data.get_buff()
        except OSError:
            logging.warning(
                "Failure to fetch the XML buffer from the manifest at %s.", path
            )
            return False
        try:
            manifest_text = minidom.parseString(initial_buff).toxml()
        except OSError:
            logging.warning("Failure to decode the XML from the manifest at %s", path)
            return False
        try:
            xmldata = BeautifulSoup(manifest_text, "xml")
        except OSError:
            logging.warning("Failure to parse XML from the manifest at %s", path)
            return False
        all_perms = xmldata.find_all("uses-permission")
        perm_list = []
        if all_perms:
            for single_permission in all_perms:
                keys = single_permission.attrs.keys()
                if keys and len(list(keys)) > 0:
                    key = list(keys)[0]
                    perm_list.append(single_permission[key])
        return perm_list


def create_apk_permlist(path):
    """
    Creates and returns the list of permissions that will be used to create the permhash.

    :param path: The path to the file where the permissions need to be retrieved
    :type perm_list: string
    """
    # Ensure the file exists, is non-zero in size, and is a mimetype that a CRX should be
    if check_type(path, APK_MIMETYPES):
        try:
            with ZipFile(path, mode="r") as apk_archive:
                if "AndroidManifest.xml" in apk_archive.namelist():
                    apk_read = apk_archive.read("AndroidManifest.xml")
                else:
                    logging.warning(
                        "This file does not include an AndroidManifest XML: %s", path
                    )
                    return False
        except (BadZipfile, OSError):
            logging.warning(
                "This APK file is corrupt and unable to be unzipped: %s.", path
            )
            return False
        try:
            apk_manifest_bytes = axml.AXMLPrinter(apk_read)
        except OSError:
            logging.warning(
                "This manifest does not appear to be an AXML file: %s.", path
            )
            return False
        if not apk_manifest_bytes.is_valid():
            logging.warning(
                "This manifest does not appear to be an AXML file: %s.", path
            )
            return False
        try:
            apk_buffer = minidom.parseString(apk_manifest_bytes.get_buff()).toxml()
            apk_xml = BeautifulSoup(apk_buffer, "xml")
        except OSError:
            logging.warning(
                "Failure to fetch and parse the XML buffer from the manifest at %s.",
                path,
            )
            return False
        all_perms = apk_xml.find_all("uses-permission")
        perm_list = []
        if all_perms:
            for single_permission in all_perms:
                keys = single_permission.attrs.keys()
                if keys and len(list(keys)) > 0:
                    key = list(keys)[0]
                    perm_list.append(single_permission[key])
        return perm_list
    return False
