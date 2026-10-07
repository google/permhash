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

import codecs
import hashlib
import json
import logging
import os
import plistlib
import struct
from xml.dom import minidom
from xml.parsers import expat
from zipfile import BadZipfile, ZipFile
import zlib

from androguard.core import axml
from bs4 import BeautifulSoup, Tag
import jstyleson
import magic
from permhash import mimetypes
import yara


MACHO_MIMETYPES = mimetypes.MACHO_MIMETYPES
IPA_MIMETYPES = mimetypes.IPA_MIMETYPES
CRX_MIMETYPES = mimetypes.CRX_MIMETYPES
CRX_MANIFEST_MIMETYPES = mimetypes.CRX_MANIFEST_MIMETYPES
APK_MIMETYPES = mimetypes.APK_MIMETYPES
APK_MANIFEST_MIMETYPES = mimetypes.APK_MANIFEST_MIMETYPES
AXMLPrinter = axml.AXMLPrinter

ENTITLEMENT_MAGIC = b"\xfa\xde\x71\x71"
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSSLOT_ENTITLEMENTS = 5
LC_CODE_SIGNATURE = 0x1D

YARA_RULES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "detect.yar"
)

try:
    YARA_RULES = yara.compile(filepath=YARA_RULES_PATH)
except (yara.Error, OSError) as err:
    logging.error("Error compiling YARA rules from %s: %s", YARA_RULES_PATH, err)
    YARA_RULES = None


def is_file(path):
    """
    Checks to see if the file exists, is not a directory, and is non-zero in size.

    :param path: The file to check.
    :type path: string
    """
    if not path or not isinstance(path, (str, bytes, os.PathLike)):
        return False
    try:
        if os.path.isfile(path):
            return bool(os.stat(path).st_size > 0)
        logging.warning(
            "This file does not exist or is a directory: (%s)",
            path,
        )
        return False
    except OSError as err:
        logging.error("Error checking file %s: %s", path, err)
        return False


def is_dir(path):
    """
    Checks to see if the given path is a directory and if it contains files.

    :param path: The path to check.
    :type path: string
    """
    if not path or not isinstance(path, (str, bytes, os.PathLike)):
        return False
    try:
        path = os.path.abspath(path)
        if os.path.isdir(path):
            files = os.listdir(path)
            if files:
                return files
            logging.warning(
                "This directory contains no files: (%s)",
                path,
            )
            return False
        logging.info(
            "This is not a directory: (%s)",
            path,
        )
        return False
    except OSError as err:
        logging.error("Directory error %s: %s", path, err)
        return False


def check_type(path, mime):
    """
    Checks to see if mime type of the file at the provided
    path is the same as one passed in variable list mime.

    :param path: The file to check.
    :type path: string
    :param mime: Potential desired mime types in a list.
    :type mime: list
    """
    if is_file(path):
        try:
            real_path = os.path.realpath(path)
            return bool(magic.from_file(real_path, mime=True) in mime)
        except (OSError, magic.MagicException) as err:
            logging.error("Error reading file %s for magic check: %s", path, err)
            return False
    return False


def parse_crx_manifest(manifest_json):
    """
    Returns the permissions from a CRX manifest json dict.

    :param manifest_json: the processed JSON manifest file dict
    """
    if not isinstance(manifest_json, dict):
        return False
    if "permissions" not in manifest_json:
        logging.warning("There are no base permissions in this manifest.")
        return False
    currentpermlist = manifest_json["permissions"]
    if not isinstance(currentpermlist, list):
        logging.warning("Manifest permissions field is not a list.")
        return False
    if all(isinstance(item, str) for item in currentpermlist):
        return currentpermlist
    newpermlist = []
    for element in currentpermlist:
        if isinstance(element, str):
            newpermlist.append(element)
        elif isinstance(element, dict) and element:
            newpermkey = str(next(iter(element.keys())))
            values = next(iter(element.values()))
            if not isinstance(values, list):
                continue
            if all(isinstance(item, str) for item in values):
                for subvalue in values:
                    newpermlist.append(f"{newpermkey}.{subvalue}")
            else:
                for perm in values:
                    if isinstance(perm, str):
                        newpermlist.append(f"{newpermkey}.{perm}")
                    elif isinstance(perm, dict) and perm:
                        embeddedpermkey = next(iter(perm.keys()))
                        embeddedpermvalue = next(iter(perm.values()))
                        newpermlist.append(
                            f"{newpermkey}.{embeddedpermkey}.{embeddedpermvalue}"
                        )
    return newpermlist


def calc_permhash(perm_list, path):
    """
    Calculates and returns the permhash from the list of permissions.

    :param perm_list: The list of string permissions
    :type perm_list: list
    :param path: The path to the file where the permissions need to be retrieved
    :type path: string
    """
    if not perm_list or isinstance(perm_list, (bool, int, float)):
        logging.warning("This file has no permissions: %s", path)
        return False
    permstr = "".join(str(p) for p in perm_list)
    return hashlib.sha256(permstr.encode("utf-8")).hexdigest()


def create_crx_permlist(path):
    """
    Creates and returns the list of permissions that will be used to create the permhash.

    :param path: The path to the file where the permissions need to be retrieved
    :type path: string
    """
    if not check_type(path, CRX_MIMETYPES):
        logging.warning(
            "This file is not a type that is currently handled (CRX): (%s)",
            path,
        )
        return False
    try:
        with ZipFile(path, mode="r") as crx_archive:
            names = crx_archive.namelist()
            manifest_entry = None
            if "manifest.json" in names:
                manifest_entry = "manifest.json"
            else:
                nested = [e for e in names if e.endswith("/manifest.json")]
                if nested:
                    nested.sort(key=lambda e: (e.count("/"), e))
                    manifest_entry = nested[0]
            if manifest_entry is None:
                logging.warning("This CRX file has no manifest: %s.", path)
                return False
            try:
                manifest_bytes = crx_archive.read(manifest_entry)
            except (RuntimeError, zlib.error, BadZipfile, EOFError, OSError):
                logging.warning(
                    "This CRX manifest is password protected and cannot be opened: %s.",
                    path,
                )
                return False
            processed_json = process_manifest_bytes(manifest_bytes)
            if not processed_json:
                logging.warning("Path: %s", path)
                return False
    except (BadZipfile, OSError):
        logging.warning(
            "This CRX file is corrupt and unable to be unzipped: %s.", path
        )
        return False
    except UnicodeDecodeError:
        logging.warning(
            "This manifest has unrecognizable and abnormal unicode issues: %s.",
            path,
        )
        return False
    perm_list = parse_crx_manifest(processed_json)
    if not perm_list:
        logging.warning("Path: %s", path)
    return perm_list


def create_crx_manifest_permlist(path):
    """
    Creates and returns the list of permissions that will be used to create the permhash.

    :param path: The path to the file where the permissions need to be retrieved
    :type path: string
    """
    if not check_type(path, CRX_MANIFEST_MIMETYPES):
        logging.warning(
            "This file is not a type that is currently handled (CRX Manifest): (%s)",
            path,
        )
        return False
    try:
        with open(path, "rb") as manifest_byte_stream:
            if manifest_byte_stream.readable():
                manifest_byte_read = manifest_byte_stream.read()
                processed_json = process_manifest_bytes(manifest_byte_read)
                if not processed_json:
                    logging.warning("Path: %s", path)
                    return False
                perm_list = parse_crx_manifest(processed_json)
                if not perm_list:
                    logging.warning("Path: %s", path)
                return perm_list
    except OSError as error:
        logging.warning("The manifest file is unable to be read: %s", error)
        logging.warning("Path: %s", path)
        return False
    return False


def _extract_apk_permissions_from_bytes(raw_bytes, path=""):
    """
    Extracts uses-permission values from raw binary AXML manifest bytes.

    :param raw_bytes: Raw bytes of AndroidManifest.xml
    :type raw_bytes: bytes
    :param path: File path for logging context
    :type path: string
    """
    if not raw_bytes:
        return False
    try:
        manifest_data = AXMLPrinter(raw_bytes)
        if not manifest_data.is_valid():
            logging.warning(
                "This manifest does not appear to be an AXML file: %s.", path
            )
            return False
        initial_buff = manifest_data.get_buff()
        manifest_text = minidom.parseString(initial_buff).toxml()
        xmldata = BeautifulSoup(manifest_text, "xml")
    except (
        OSError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        struct.error,
        zlib.error,
        NotImplementedError,
        EOFError,
        expat.ExpatError,
    ) as err:
        logging.warning("Failure to parse XML from the manifest at %s: %s", path, err)
        return False

    all_perms = xmldata.find_all("uses-permission")
    perm_list = []
    if all_perms:
        for single_permission in all_perms:
            if isinstance(single_permission, Tag) and single_permission.attrs:
                perm_val = single_permission.attrs.get(
                    "android:name"
                ) or single_permission.attrs.get("name")
                if perm_val is None:
                    first_key = next(iter(single_permission.attrs.keys()))
                    perm_val = single_permission[first_key]
                if isinstance(perm_val, str):
                    perm_list.append(perm_val)
    return perm_list


def create_apk_manifest_permlist(path):
    """
    Creates and returns the list of permissions that will be used to create the permhash.

    :param path: The path to the file where the permissions need to be retrieved
    :type path: string
    """
    if not check_type(path, APK_MANIFEST_MIMETYPES):
        logging.warning(
            "This file is not a type that is currently handled (APK Manifest): (%s)",
            path,
        )
        return False
    try:
        with open(path, "rb") as manifest:
            raw_bytes = manifest.read()
    except OSError as err:
        logging.warning("This APK manifest is not readable: %s (%s)", path, err)
        return False
    return _extract_apk_permissions_from_bytes(raw_bytes, path)


def create_apk_permlist(path):
    """
    Creates and returns the list of permissions that will be used to create the permhash.

    :param path: The path to the file where the permissions need to be retrieved
    :type path: string
    """
    if not check_type(path, APK_MIMETYPES):
        logging.warning(
            "This file is not a type that is currently handled (APK): (%s)",
            path,
        )
        return False
    try:
        with ZipFile(path, mode="r") as apk_archive:
            if "AndroidManifest.xml" in apk_archive.namelist():
                apk_read = apk_archive.read("AndroidManifest.xml")
            else:
                logging.warning(
                    "This file does not include an AndroidManifest XML: %s", path
                )
                return False
    except (
        BadZipfile,
        RuntimeError,
        zlib.error,
        EOFError,
        KeyError,
        OSError,
    ):
        logging.warning(
            "This APK file is likely corrupt or inaccessible and unable to be unzipped: %s.",
            path,
        )
        return False

    return _extract_apk_permissions_from_bytes(apk_read, path)


def strip_comments(manifest_text):
    """
    Strips the manifest of comments so the json can be loaded and manipulated.

    :param manifest_text: A read manifest text file from input
    :type manifest_text: string
    """
    if not isinstance(manifest_text, str):
        return False
    try:
        stripped_manifest = jstyleson.loads(manifest_text)
        return stripped_manifest if isinstance(stripped_manifest, dict) else False
    except (ValueError, json.decoder.JSONDecodeError) as error:
        try:
            stripped_manifest = jstyleson.loads(
                manifest_text.encode().decode("utf-8-sig")
            )
            return (
                stripped_manifest
                if isinstance(stripped_manifest, dict)
                else False
            )
        except (ValueError, UnicodeError, json.decoder.JSONDecodeError):
            logging.warning("This manifest file is abnormal and unable to be read")
            logging.warning(str(error))
            return False


def process_manifest_bytes(manifest_byte_read):
    """
    Processes CRX manifest bytes to remove or convert abnormal encodings/characters.

    :param manifest_byte_read: A read manifest file from input
    :type manifest_byte_read: bytes
    """
    if not isinstance(manifest_byte_read, (bytes, bytearray)):
        return False
    if manifest_byte_read.startswith(codecs.BOM_UTF8):
        manifest_byte_read = manifest_byte_read[len(codecs.BOM_UTF8) :]
    try:
        manifest_json = json.loads(manifest_byte_read)
        return manifest_json if isinstance(manifest_json, dict) else False
    except UnicodeDecodeError as error:
        try:
            decoded_json = codecs.decode(manifest_byte_read, "iso-8859-1")
            try:
                manifest_json = json.loads(decoded_json)
                return manifest_json if isinstance(manifest_json, dict) else False
            except json.decoder.JSONDecodeError:
                return strip_comments(decoded_json)
        except UnicodeDecodeError:
            logging.warning("There was an error decoding/loading the json.")
            logging.warning(str(error))
            return False
    except json.decoder.JSONDecodeError as error:
        try:
            return strip_comments(manifest_byte_read.decode("utf-8"))
        except UnicodeDecodeError:
            logging.warning("The manifest file is improperly formatted.")
            logging.warning(str(error))
            return False


def _has_plist_header_within(buf, offset, window=300):
    """Returns True if buf[offset : offset + window] contains <?xml or <plist."""
    chunk = buf[offset : offset + window]
    return b"<?xml" in chunk or b"<plist" in chunk


def extract_xml(bytes_dump):
    """
    Extracts all entitlement XML byte sections from a Mach-O byte buffer.

    :param bytes_dump: File bytes expected to have an XML section
    :type bytes_dump: bytes
    """
    if not isinstance(bytes_dump, (bytes, bytearray)):
        return []
    results = []
    search_offset = 0
    total_len = len(bytes_dump)
    while search_offset < total_len:
        start_index = bytes_dump.find(ENTITLEMENT_MAGIC, search_offset)
        if start_index == -1:
            break
        search_offset = start_index + 4
        if not _has_plist_header_within(bytes_dump, start_index):
            continue
        slice_end = total_len
        if start_index + 8 <= total_len:
            blob_len = struct.unpack(
                ">I", bytes_dump[start_index + 4 : start_index + 8]
            )[0]
            if 8 < blob_len <= total_len - start_index:
                slice_end = start_index + blob_len
        probe = search_offset
        while probe < slice_end:
            next_magic = bytes_dump.find(ENTITLEMENT_MAGIC, probe, slice_end)
            if next_magic == -1:
                break
            if _has_plist_header_within(bytes_dump, next_magic):
                slice_end = next_magic
                break
            probe = next_magic + 4
        candidate = bytes_dump[start_index:slice_end]
        xml_start = candidate.find(b"<?xml")
        if xml_start == -1 or xml_start >= 300:
            plist_start = candidate.find(b"<plist")
            if plist_start != -1 and plist_start < 300:
                xml_start = plist_start
            else:
                continue
        end_index = candidate.find(b"</plist>", xml_start)
        if end_index != -1:
            results.append(bytes(candidate[xml_start : end_index + 8]))
    return results


def _get_macho_slices(macho_bytes):
    """
    Returns (slice_offset, slice_size) pairs for thin or Universal/Fat Mach-O.

    :param macho_bytes: Raw bytes of a thin or Universal/Fat Mach-O binary
    :type macho_bytes: bytes
    """
    if not isinstance(macho_bytes, (bytes, bytearray)) or len(macho_bytes) < 28:
        return []
    total_len = len(macho_bytes)
    magic_be = struct.unpack(">I", macho_bytes[:4])[0]
    slices = []
    if magic_be in (0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA):
        fat_endian = ">" if magic_be in (0xCAFEBABE, 0xCAFEBABF) else "<"
        is_fat64 = magic_be in (0xCAFEBABF, 0xBFBAFECA)
        nfat_arch = struct.unpack(fat_endian + "I", macho_bytes[4:8])[0]
        if 0 < nfat_arch <= 64:
            arch_offset = 8
            arch_size = 32 if is_fat64 else 20
            for _ in range(nfat_arch):
                if arch_offset + arch_size > total_len:
                    break
                if is_fat64:
                    _, _, offset, size, _, _ = struct.unpack(
                        fat_endian + "IIQQII",
                        macho_bytes[arch_offset : arch_offset + 32],
                    )
                else:
                    _, _, offset, size, _ = struct.unpack(
                        fat_endian + "IIIII",
                        macho_bytes[arch_offset : arch_offset + 20],
                    )
                arch_offset += arch_size
                if (
                    0 <= offset
                    and size >= 28
                    and offset + size <= total_len
                    and struct.unpack(">I", macho_bytes[offset : offset + 4])[0]
                    in (0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE)
                ):
                    slices.append((offset, size))
    if not slices:
        slices.append((0, total_len))
    return slices


def _extract_slice_cs_blobs(macho_bytes, slice_offset, slice_size):
    """
    Extracts LC_CODE_SIGNATURE entitlement XML blobs from a single Mach-O slice.
    """
    total_len = len(macho_bytes)
    if slice_offset + 28 > total_len:
        return []
    s_magic = struct.unpack(">I", macho_bytes[slice_offset : slice_offset + 4])[0]
    if s_magic == 0xFEEDFACE:
        endian, hdr_size = ">", 28
    elif s_magic == 0xCEFAEDFE:
        endian, hdr_size = "<", 28
    elif s_magic == 0xFEEDFACF:
        endian, hdr_size = ">", 32
    elif s_magic == 0xCFFAEDFE:
        endian, hdr_size = "<", 32
    else:
        return []
    if slice_offset + hdr_size > total_len:
        return []
    ncmds, sizeofcmds = struct.unpack(
        endian + "II", macho_bytes[slice_offset + 16 : slice_offset + 24]
    )
    if ncmds == 0 or ncmds > 4096 or sizeofcmds == 0:
        return []
    slot5_blobs = []
    other_cs_blobs = []
    cmd_offset = slice_offset + hdr_size
    cmds_end = min(slice_offset + slice_size, cmd_offset + sizeofcmds, total_len)
    for _ in range(ncmds):
        if cmd_offset + 8 > cmds_end:
            break
        cmd, cmdsize = struct.unpack(
            endian + "II", macho_bytes[cmd_offset : cmd_offset + 8]
        )
        if cmdsize < 8 or cmd_offset + cmdsize > cmds_end:
            break
        if cmd == LC_CODE_SIGNATURE and cmdsize >= 16:
            dataoff, datasize = struct.unpack(
                endian + "II", macho_bytes[cmd_offset + 8 : cmd_offset + 16]
            )
            cs_start = slice_offset + dataoff
            cs_end = min(slice_offset + slice_size, cs_start + datasize, total_len)
            if cs_start + 8 <= cs_end:
                cs_magic, cs_len = struct.unpack(
                    ">II", macho_bytes[cs_start : cs_start + 8]
                )
                if cs_magic == CSMAGIC_EMBEDDED_SIGNATURE and cs_start + 12 <= cs_end:
                    count = struct.unpack(
                        ">I", macho_bytes[cs_start + 8 : cs_start + 12]
                    )[0]
                    idx_pos = cs_start + 12
                    for _ in range(min(count, 256)):
                        if idx_pos + 8 > cs_end:
                            break
                        slot_type, blob_rel_off = struct.unpack(
                            ">II", macho_bytes[idx_pos : idx_pos + 8]
                        )
                        idx_pos += 8
                        blob_abs = cs_start + blob_rel_off
                        if blob_abs + 8 <= cs_end:
                            b_magic, b_len = struct.unpack(
                                ">II", macho_bytes[blob_abs : blob_abs + 8]
                            )
                            if b_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS and b_len >= 8:
                                b_end = min(cs_end, blob_abs + b_len)
                                extracted = extract_xml(macho_bytes[blob_abs:b_end])
                                if slot_type == CSSLOT_ENTITLEMENTS:
                                    slot5_blobs.extend(extracted)
                                else:
                                    other_cs_blobs.extend(extracted)
                elif cs_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS and cs_len >= 8:
                    b_end = min(cs_end, cs_start + cs_len)
                    slot5_blobs.extend(extract_xml(macho_bytes[cs_start:b_end]))
        cmd_offset += cmdsize
    return slot5_blobs + other_cs_blobs


def _extract_cs_entitlement_blobs(macho_bytes):
    """
    Extracts entitlement XML blobs from Mach-O LC_CODE_SIGNATURE commands.

    :param macho_bytes: Raw bytes of a thin or Universal/Fat Mach-O binary
    :type macho_bytes: bytes
    """
    blobs = []
    for slice_offset, slice_size in _get_macho_slices(macho_bytes):
        blobs.extend(_extract_slice_cs_blobs(macho_bytes, slice_offset, slice_size))
    return blobs


def _parse_plist_keys(xml_blobs, path=""):
    """
    Parses XML plist blobs and returns unique dictionary keys in order.

    :param xml_blobs: A list of XML byte sections
    :type xml_blobs: list
    :param path: Path string for logging context
    :type path: string
    """
    if isinstance(xml_blobs, (bytes, bytearray)):
        xml_blobs = [xml_blobs] if xml_blobs else []
    keys = []
    seen = set()
    for xml_bytes in xml_blobs:
        if not xml_bytes:
            continue
        try:
            plist = plistlib.loads(xml_bytes)
        except (
            plistlib.InvalidFileException,
            expat.ExpatError,
            ValueError,
            TypeError,
            OverflowError,
            RecursionError,
        ) as plist_error:
            logging.warning(
                "The entitlements were unable to be loaded: %s (%s).",
                path,
                plist_error,
            )
            continue
        if isinstance(plist, dict):
            for k in plist.keys():
                k_str = str(k)
                if k_str not in seen:
                    seen.add(k_str)
                    keys.append(k_str)
    return keys


def _extract_macho_entitlement_keys(macho_bytes, path=""):
    """
    Validates YARA entitlement rule on Mach-O bytes and extracts plist keys.

    :param macho_bytes: Raw Mach-O binary bytes
    :type macho_bytes: bytes
    :param path: Path string for logging context
    :type path: string
    """
    if not macho_bytes or not YARA_RULES:
        return []
    try:
        yara_matches = YARA_RULES.match(data=macho_bytes)
    except yara.Error as err:
        logging.warning("YARA matching failed for %s: %s", path, err)
        return []
    if not any(
        match.rule == "M_Hunting_MachO_Entitlements_1" for match in yara_matches
    ):
        return []

    keys = []
    seen = set()
    for slice_offset, slice_size in _get_macho_slices(macho_bytes):
        cs_blobs = _extract_slice_cs_blobs(macho_bytes, slice_offset, slice_size)
        slice_keys = _parse_plist_keys(cs_blobs, path) if cs_blobs else []
        if not slice_keys:
            slice_bytes = macho_bytes[slice_offset : slice_offset + slice_size]
            slice_keys = _parse_plist_keys(extract_xml(slice_bytes), path)
        for k in slice_keys:
            if k not in seen:
                seen.add(k)
                keys.append(k)

    if keys:
        return keys
    return _parse_plist_keys(extract_xml(macho_bytes), path)


def confirm_macho(path, file_bytes):
    """
    Confirm the file at path with the file bytes file_bytes is a Mach-O file.
    Returns true if it is a Mach-O file.

    :param path: string to the path of the file being assessed
    :type path: string
    :param file_bytes: the bytes read of the file being assessed
    :type file_bytes: bytes
    """
    if check_type(path, MACHO_MIMETYPES) and YARA_RULES and file_bytes:
        try:
            yara_matches = YARA_RULES.match(data=file_bytes)
            return any(
                match.rule == "M_Hunting_MachO_Entitlements_1"
                for match in yara_matches
            )
        except yara.Error as err:
            logging.warning("YARA error for %s: %s", path, err)
    return False


def _find_ipa_executable_paths(ipa_unzip):
    """
    Locates candidate main Mach-O executable paths inside an IPA archive.
    Prioritizes CFBundleExecutable from Payload/<App>.app/Info.plist over the
    Payload/<App>.app/<App> directory-name heuristic.

    :param ipa_unzip: An open ZipFile object for the IPA
    :type ipa_unzip: ZipFile
    """
    namelist = ipa_unzip.namelist()
    candidates = []
    for entry in namelist:
        if entry.startswith("Payload/") and not entry.endswith("/"):
            parts = entry.split("/")
            if (
                len(parts) == 3
                and parts[1].lower().endswith(".app")
                and parts[2] == "Info.plist"
            ):
                try:
                    info_plist = plistlib.loads(ipa_unzip.read(entry))
                    if isinstance(info_plist, dict):
                        cf_exec = info_plist.get("CFBundleExecutable")
                        if (
                            isinstance(cf_exec, str)
                            and cf_exec
                            and "/" not in cf_exec
                        ):
                            candidate = f"Payload/{parts[1]}/{cf_exec}"
                            if candidate in namelist and candidate not in candidates:
                                candidates.append(candidate)
                except (
                    plistlib.InvalidFileException,
                    expat.ExpatError,
                    ValueError,
                    KeyError,
                    BadZipfile,
                    RuntimeError,
                    zlib.error,
                    EOFError,
                    OSError,
                ):
                    continue

    for entry in namelist:
        if entry.startswith("Payload/") and not entry.endswith("/"):
            parts = entry.split("/")
            if len(parts) == 3 and parts[1].lower().endswith(".app"):
                exec_name = parts[1][:-4]
                if (
                    exec_name
                    and parts[2].lower() == exec_name.lower()
                    and entry not in candidates
                ):
                    candidates.append(entry)
    return candidates


def _find_ipa_executable_path(ipa_unzip):
    """
    Locates the highest-priority main Mach-O executable path inside an IPA archive.

    :param ipa_unzip: An open ZipFile object for the IPA
    :type ipa_unzip: ZipFile
    """
    candidates = _find_ipa_executable_paths(ipa_unzip)
    return candidates[0] if candidates else None


def create_ipa_permlist(path):
    """
    Create the list of the entitlements by the keys within the plist and return these values.

    :param path: string to the path of the file being assessed
    :type path: string
    """
    if not check_type(path, IPA_MIMETYPES):
        logging.warning(
            "This file is not a type that is currently handled (IPA): (%s)",
            path,
        )
        return []
    try:
        with open(path, mode="rb") as gf:
            if gf.read(4) != b"PK\x03\x04":
                logging.warning("Not a valid ZIP/IPA file: %s", path)
                return []
            gf.seek(0)
            with ZipFile(gf, "r") as ipa_unzip:
                candidate_paths = _find_ipa_executable_paths(ipa_unzip)
                if not candidate_paths:
                    logging.warning(
                        "Could not find main executable in IPA: %s", path
                    )
                    return []
                for macho_path in candidate_paths:
                    try:
                        macho_bytes = ipa_unzip.read(macho_path)
                    except (
                        KeyError,
                        BadZipfile,
                        RuntimeError,
                        zlib.error,
                        EOFError,
                        OSError,
                    ) as read_error:
                        logging.warning(
                            "The Mach-O in this IPA is unable to be read: %s (%s).",
                            path,
                            read_error,
                        )
                        continue
                    keys = _extract_macho_entitlement_keys(macho_bytes, path)
                    if keys:
                        return keys
                return []
    except (BadZipfile, OSError, yara.Error) as err:
        logging.warning("This IPA is unable to be processed: %s (%s).", path, err)
        return []


def create_macho_permlist(path):
    """
    Create the list of the entitlements by the keys within the plist and return these values.

    :param path: string to the path of the file being assessed
    :type path: string
    """
    if not is_file(path):
        return []
    try:
        with open(path, mode="rb") as macho_read:
            macho_bytes = macho_read.read()
    except OSError as read_error:
        logging.warning(
            "The Mach-O at the following path was unable to be read: %s (%s).",
            path,
            read_error,
        )
        return []
    if not check_type(path, MACHO_MIMETYPES) and macho_bytes[:4] not in (
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    ):
        logging.warning(
            "This file is not a type that is currently handled (Mach-O): (%s)",
            path,
        )
        return []
    return _extract_macho_entitlement_keys(macho_bytes, path)
