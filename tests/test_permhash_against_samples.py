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

import hashlib
import os
import plistlib
import struct
import sys
from unittest import mock
import zipfile

from permhash import functions
from permhash import helpers
from permhash.scripts import cli


TEST_FILES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "test_files"
)

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
CPU_SUBTYPE_ALL = 0x00000003
MH_EXECUTE = 2
ENT_MAGIC = b"\xfa\xde\x71\x71"

BENIGN_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<plist version="1.0">'
    b"<dict>"
    b"<key>com.apple.security.app-sandbox</key><true/>"
    b"</dict>"
    b"</plist>"
)

DANGEROUS_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<plist version="1.0">'
    b"<dict>"
    b"<key>com.apple.private.tcc.allow</key>"
    b"<array><string>kTCCServiceSystemPolicyAllFiles</string></array>"
    b"<key>task_for_pid-allow</key><true/>"
    b"</dict>"
    b"</plist>"
)


def _test_file(name):
    return os.path.join(TEST_FILES_DIR, name)


def _make_entitlement_blob(xml_body):
    return ENT_MAGIC + struct.pack(">I", 8 + len(xml_body)) + xml_body


def _make_macho_header(ncmds=0, sizeofcmds=0):
    return struct.pack(
        "<IiiIIIII",
        MH_MAGIC_64,
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_ALL,
        MH_EXECUTE,
        ncmds,
        sizeofcmds,
        0,
        0,
    )


def _make_macho_with_lc_code_signature(ent_xml, decoy_xml=None):
    ent_blob = _make_entitlement_blob(ent_xml)
    superblob_hdr = struct.pack(">III", 0xFADE0CC0, 20 + len(ent_blob), 1)
    blob_index = struct.pack(">II", 5, 20)
    superblob = superblob_hdr + blob_index + ent_blob

    decoy_section = (
        b"\x00" * 32 + _make_entitlement_blob(decoy_xml) + b"\x00" * 32
        if decoy_xml
        else b"\x00" * 64
    )
    hdr_and_cmd_size = 32 + 16
    cs_offset = hdr_and_cmd_size + len(decoy_section)
    lc_codesig = struct.pack("<IIII", 0x1D, 16, cs_offset, len(superblob))
    mach_hdr = _make_macho_header(ncmds=1, sizeofcmds=16)
    return mach_hdr + lc_codesig + decoy_section + superblob


def test_crx_manifest_legitimate():
    """
    Tests the permhash calculation of a CRX manifest file.
    The desired result should be def81bd23e3754f4b9708c89e975f0e6af7d3d84e03e089226fda7e263f8fb53
    def81bd23e3754f4b9708c89e975f0e6af7d3d84e03e089226fda7e263f8fb53 is the hash of
    "activeTabidentityidentity.emailcontextMenusstoragetabsunlimitedStoragescripting"
    """
    assert (
        functions.permhash_crx_manifest(
            _test_file(
                "c400b87cd89724f00b443bfb8cbd14f0f05757348a730f39b14040b25b3a74ef"
            )
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
            _test_file(
                "9a3160dcb6dc459daeeea94b0acfdec30c48dba040a712c9940489eebd734992"
            )
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
            _test_file(
                "aa18e880de24b87cb976609a6ee55f306eae5c7919683b1fc4782daade846f04"
            )
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
            _test_file(
                "069ccbc9ee6fda32e0995937158790aadc9356313a0f8ea1564883714accd527"
            )
        )
        is False
    )
    assert (
        functions.permhash_apk(
            _test_file(
                "563caca7686debdfada1d03d850fc935ca44cdb1b045bad8496a32c35b1950fb"
            )
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
            _test_file(
                "114a0709d58da99b61a08c8a0fb4ae099831b633717110957be6f9ff04747c11"
            )
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
            _test_file(
                "1b3e9577a90a6d6aae50b15ae8a837c05205de6f6c3b6b5e00dc97fb791ec4ba"
            )
        )
        is False
    )
    assert (
        functions.permhash_crx_manifest(
            _test_file(
                "09c801371536abc0dbadd7b0561ef837f227b410e9e273e035fa1b910c1aa088"
            )
        )
        is False
    )
    assert (
        functions.permhash_crx_manifest(
            _test_file(
                "171f68fb1c511ae3c7f2bec28ccff6b802102266c85cd64c540e083e888228c0"
            )
        )
        is False
    )


def test_manifest_with_comments():
    """
    Tests the permhash calculation of samples with comments in the manifest.
    """
    assert (
        functions.permhash_crx_manifest(
            _test_file(
                "eb6b894d0f8688a06970d19f3ff0f963fe7d5554cd190984be8b68d9296350d4"
            )
        )
        == "c1794090365f03b81f1e6e9fa678788a43d2d3bac2d1d854e415f3c09fbcfe86"
    )


def test_manifest_that_is_stomped():
    """
    Tests the permhash calculation of samples with a truncated manifest.
    The desired result should be False
    """
    assert (
        functions.permhash_crx_manifest(
            _test_file(
                "17308c8b11d64cd0bd54eb576c5ee182b803c84e2ea7884065e39b4055d863e8"
            )
        )
        is False
    )


def test_apk_nonaxml():
    """
    Tests the permhash calculation of samples with non-axml files.
    The desired result should be False
    """
    sample = _test_file(
        "12073711df9d41dd7ec838a799a3a0114bb1822a37427e353d464eb771ceec73"
    )
    assert functions.permhash_crx_manifest(sample) is False
    assert functions.permhash_apk(sample) is False


def test_ipa():
    """
    Tests the permhash calculation of an IPA sample.
    """
    assert (
        functions.permhash_ipa(
            _test_file(
                "093df6f30e0ef06e42b40bde4fea08c27a1a623bb0b6f6b363242931ab0247e2"
            )
        )
        == "27fada76cc72ce4a9b821cecfd2c93289bbf2eaac171388d3a7d0e5b4adaf63b"
    )


def test_macho():
    """
    Tests the permhash calculation of a mach-o sample.
    """
    assert (
        functions.permhash_macho(
            _test_file(
                "e82182d7635ca7bd13ef34f92ccd4cfdc4c26cae0f3a2a2d28da5637ca0766a1"
            )
        )
        == "27fada76cc72ce4a9b821cecfd2c93289bbf2eaac171388d3a7d0e5b4adaf63b"
    )


def test_macho_decoy_entitlement_spoofing_prevented(tmp_path):
    """
    Verifies a decoy 0xfade7171 blob cannot spoof Mach-O permhash.
    """
    benign_blob = _make_entitlement_blob(BENIGN_XML)
    dangerous_blob = _make_entitlement_blob(DANGEROUS_XML)
    hdr = _make_macho_header()
    pad_small = b"\x00" * 64
    pad_gap = b"\x00" * 1024

    benign_path = tmp_path / "benign.macho"
    honest_path = tmp_path / "honest.macho"
    evil_path = tmp_path / "evil.macho"

    benign_path.write_bytes(hdr + pad_small + benign_blob)
    honest_path.write_bytes(hdr + pad_small + dangerous_blob)
    evil_path.write_bytes(
        hdr + pad_small + benign_blob + pad_gap + dangerous_blob
    )

    h_benign = functions.permhash_macho(str(benign_path))
    h_honest = functions.permhash_macho(str(honest_path))
    h_evil = functions.permhash_macho(str(evil_path))

    assert h_benign and h_honest and h_evil
    assert h_benign != h_honest
    assert h_evil != h_benign
    assert helpers.confirm_macho(str(benign_path), benign_path.read_bytes())
    carved = helpers.extract_xml(evil_path.read_bytes())
    assert isinstance(carved, list) and len(carved) == 2
    assert any(b"task_for_pid-allow" in blob for blob in carved)


def test_macho_lc_code_signature_ignores_decoy(tmp_path):
    """
    Verifies LC_CODE_SIGNATURE slot 5 entitlements ignore decoy blobs.
    """
    honest_bytes = _make_macho_with_lc_code_signature(DANGEROUS_XML)
    evil_bytes = _make_macho_with_lc_code_signature(
        DANGEROUS_XML, decoy_xml=BENIGN_XML
    )

    honest_path = tmp_path / "honest_cs.macho"
    evil_path = tmp_path / "evil_cs.macho"
    honest_path.write_bytes(honest_bytes)
    evil_path.write_bytes(evil_bytes)

    h_honest = functions.permhash_macho(str(honest_path))
    h_evil = functions.permhash_macho(str(evil_path))
    expected = hashlib.sha256(
        b"com.apple.private.tcc.allowtask_for_pid-allow"
    ).hexdigest()
    assert h_honest == expected
    assert h_evil == expected


def test_macho_fat_binary_entitlements(tmp_path):
    """
    Verifies Universal/Fat Mach-O binaries extract LC_CODE_SIGNATURE entitlements.
    """
    slice_bytes = _make_macho_with_lc_code_signature(
        DANGEROUS_XML, decoy_xml=BENIGN_XML
    )
    slice_offset = 4096
    fat_header = struct.pack(
        ">IIIII",
        0xCAFEBABE,
        1,
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_ALL,
        slice_offset,
    ) + struct.pack(">II", len(slice_bytes), 12)
    fat_bytes = fat_header.ljust(slice_offset, b"\x00") + slice_bytes

    fat_path = tmp_path / "fat.macho"
    fat_path.write_bytes(fat_bytes)

    expected = hashlib.sha256(
        b"com.apple.private.tcc.allowtask_for_pid-allow"
    ).hexdigest()
    assert functions.permhash_macho(str(fat_path)) == expected


def test_macho_fat_multi_slice_mixed_cs_and_raw_entitlements(tmp_path):
    """
    Verifies multi-slice Fat Mach-O extracts entitlements across signed and unsigned slices.
    """
    slice0 = _make_macho_with_lc_code_signature(BENIGN_XML)
    slice1 = (
        _make_macho_header()
        + b"\x00" * 64
        + _make_entitlement_blob(DANGEROUS_XML)
    )
    off0 = 4096
    off1 = 8192
    fat_hdr = (
        struct.pack(">II", 0xCAFEBABE, 2)
        + struct.pack(
            ">IIIII", CPU_TYPE_X86_64, CPU_SUBTYPE_ALL, off0, len(slice0), 12
        )
        + struct.pack(">IIIII", 0x0100000C, 0, off1, len(slice1), 12)
    )
    fat_bytes = (
        fat_hdr.ljust(off0, b"\x00")
        + slice0.ljust(off1 - off0, b"\x00")
        + slice1
    )
    fat_path = tmp_path / "fat_multi.macho"
    fat_path.write_bytes(fat_bytes)

    expected = hashlib.sha256(
        b"com.apple.security.app-sandbox"
        b"com.apple.private.tcc.allow"
        b"task_for_pid-allow"
    ).hexdigest()
    assert functions.permhash_macho(str(fat_path)) == expected


def test_macho_fat64_binary_entitlements(tmp_path):
    """
    Verifies 64-bit Universal/Fat Mach-O (0xcafebabf) extracts entitlements.
    """
    slice_bytes = _make_macho_with_lc_code_signature(DANGEROUS_XML)
    slice_offset = 4096
    fat64_hdr = struct.pack(">II", 0xCAFEBABF, 1) + struct.pack(
        ">IIQQII",
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_ALL,
        slice_offset,
        len(slice_bytes),
        12,
        0,
    )
    fat64_bytes = fat64_hdr.ljust(slice_offset, b"\x00") + slice_bytes
    fat64_path = tmp_path / "fat64.macho"
    fat64_path.write_bytes(fat64_bytes)

    expected = hashlib.sha256(
        b"com.apple.private.tcc.allowtask_for_pid-allow"
    ).hexdigest()
    assert functions.permhash_macho(str(fat64_path)) == expected


def test_macho_early_bare_entitlement_magic_bytes(tmp_path):
    """
    Verifies bare 0xfade7171 >300 bytes before real blob does not blind YARA or extract_xml.
    """
    hdr = _make_macho_header()
    dangerous_blob = _make_entitlement_blob(DANGEROUS_XML)
    macho_bytes = (
        hdr + b"\x00" * 32 + ENT_MAGIC + b"\x00" * 600 + dangerous_blob
    )

    macho_path = tmp_path / "early_magic.macho"
    macho_path.write_bytes(macho_bytes)

    expected = hashlib.sha256(
        b"com.apple.private.tcc.allowtask_for_pid-allow"
    ).hexdigest()
    assert functions.permhash_macho(str(macho_path)) == expected


def test_macho_embedded_magic_inside_plist_body(tmp_path):
    """
    Verifies bare 0xfade7171 inside a plist body does not truncate extract_xml.
    """
    xml_with_embedded_magic = (
        b'<?xml version="1.0" encoding="ISO-8859-1"?>'
        b'<plist version="1.0">'
        b"<dict>"
        b"<key>com.apple.private.tcc.allow</key>"
        b"<data>APreccaR</data>"
        b"<!-- " + ENT_MAGIC + b" -->"
        b"<key>task_for_pid-allow</key><true/>"
        b"</dict>"
        b"</plist>"
    )
    hdr = _make_macho_header()
    blob = _make_entitlement_blob(xml_with_embedded_magic)
    macho_path = tmp_path / "embedded_magic_in_plist.macho"
    macho_path.write_bytes(hdr + b"\x00" * 32 + blob)

    expected = hashlib.sha256(
        b"com.apple.private.tcc.allowtask_for_pid-allow"
    ).hexdigest()
    assert functions.permhash_macho(str(macho_path)) == expected


def test_macho_unclosed_decoy_plist_bounded(tmp_path):
    """
    Verifies unclosed decoy <plist with forged length cannot swallow real blob.
    """
    hdr = _make_macho_header()
    unclosed_decoy = (
        b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">'
        b"<dict><key>decoy</key><true/>"
    )
    dangerous_blob = _make_entitlement_blob(DANGEROUS_XML)
    forged_len = 8 + len(unclosed_decoy) + 64 + len(dangerous_blob)
    decoy_blob = ENT_MAGIC + struct.pack(">I", forged_len) + unclosed_decoy
    macho_bytes = (
        hdr + b"\x00" * 32 + decoy_blob + b"\x00" * 64 + dangerous_blob
    )

    macho_path = tmp_path / "unclosed_decoy.macho"
    macho_path.write_bytes(macho_bytes)

    expected = hashlib.sha256(
        b"com.apple.private.tcc.allowtask_for_pid-allow"
    ).hexdigest()
    assert functions.permhash_macho(str(macho_path)) == expected


def test_ipa_decoy_spoofing_and_cfbundleexecutable(tmp_path):
    """
    Verifies IPA prevents decoy spoofing and prioritizes Info.plist CFBundleExecutable over decoy <App> binary.
    """
    macho_bytes = _make_macho_with_lc_code_signature(
        DANGEROUS_XML, decoy_xml=BENIGN_XML
    )
    decoy_app_macho = _make_macho_with_lc_code_signature(BENIGN_XML)
    info_plist_bytes = plistlib.dumps({"CFBundleExecutable": "CustomRunner"})

    ipa_path = tmp_path / "test.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr("Payload/MyApp.app/MyApp", decoy_app_macho)
        zf.writestr("Payload/MyApp.app/Info.plist", info_plist_bytes)
        zf.writestr("Payload/MyApp.app/CustomRunner", macho_bytes)

    expected = hashlib.sha256(
        b"com.apple.private.tcc.allowtask_for_pid-allow"
    ).hexdigest()
    assert functions.permhash_ipa(str(ipa_path)) == expected


def test_crx_root_manifest_priority_over_nested_decoy(tmp_path):
    """
    Verifies root manifest.json takes precedence over nested a/manifest.json and z/manifest.json.
    """
    crx_path = tmp_path / "ext.zip"
    with zipfile.ZipFile(crx_path, "w") as zf:
        zf.writestr("a/manifest.json", b'{"permissions": ["storage"]}')
        zf.writestr("manifest.json", b'{"permissions": ["tabs", "cookies"]}')
        zf.writestr("z/manifest.json", b'{"permissions": ["alarms"]}')

    expected = hashlib.sha256(b"tabscookies").hexdigest()
    assert functions.permhash_crx(str(crx_path)) == expected


def test_crx_nested_manifest_fallback(tmp_path):
    """
    Verifies nested manifest.json is used when root manifest.json is absent.
    """
    crx_path = tmp_path / "nested_ext.zip"
    with zipfile.ZipFile(crx_path, "w") as zf:
        zf.writestr(
            "subdir/manifest.json", b'{"permissions": ["tabs", "cookies"]}'
        )

    expected = hashlib.sha256(b"tabscookies").hexdigest()
    assert functions.permhash_crx(str(crx_path)) == expected


def test_crx_complex_and_malformed_permissions():
    """
    Tests parse_crx_manifest with nested dicts and malformed elements.
    """
    manifest = {
        "permissions": [
            "activeTab",
            {"fileSystem": ["write", "retainEntries"]},
            {"usbDevices": [{"vendorId": 1155}, {"productId": 57105}]},
            {},
            {"bad": "not_a_list"},
            123,
        ]
    }
    perms = helpers.parse_crx_manifest(manifest)
    assert perms == [
        "activeTab",
        "fileSystem.write",
        "fileSystem.retainEntries",
        "usbDevices.vendorId.1155",
        "usbDevices.productId.57105",
    ]
    assert helpers.parse_crx_manifest(["not", "a", "dict"]) is False
    assert helpers.parse_crx_manifest({"permissions": "not_a_list"}) is False


def test_apk_attribute_order_invariance():
    """
    Verifies uses-permission extracts android:name regardless of attribute order.
    """
    xml_bytes = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        b'<uses-permission android:maxSdkVersion="28" '
        b'android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>'
        b'<uses-permission android:name="android.permission.INTERNET"/>'
        b'<uses-permission value="android.permission.CAMERA"/>'
        b"</manifest>"
    )
    with mock.patch.object(helpers, "AXMLPrinter") as mock_printer:
        instance = mock_printer.return_value
        instance.is_valid.return_value = True
        instance.get_buff.return_value = xml_bytes
        perms = helpers._extract_apk_permissions_from_bytes(
            b"dummy_axml", "dummy"
        )
    assert perms == [
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    ]


def test_malformed_and_edge_case_inputs(tmp_path):
    """
    Verifies malformed and empty inputs return False/[] without unhandled exceptions.
    """
    empty_file = tmp_path / "empty"
    empty_file.write_bytes(b"")
    assert functions.permhash_crx(str(empty_file)) is False
    assert functions.permhash_crx_manifest(str(empty_file)) is False
    assert functions.permhash_apk(str(empty_file)) is False
    assert functions.permhash_apk_manifest(str(empty_file)) is False
    assert functions.permhash_ipa(str(empty_file)) is False
    assert functions.permhash_macho(str(empty_file)) is False

    nonexistent = str(tmp_path / "does_not_exist")
    assert functions.permhash_crx(nonexistent) is False
    assert functions.permhash_ipa(nonexistent) is False
    assert functions.permhash_macho(nonexistent) is False

    non_dict_plist = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<plist version="1.0"><string>not_a_dict</string></plist>'
    )
    assert helpers._parse_plist_keys([non_dict_plist], "test") == []


def test_cli_single_file_and_directory_modes(tmp_path, capsys):
    """
    Verifies CLI handles both single files and directories properly.
    """
    m1 = tmp_path / "m1.json"
    m2 = tmp_path / "m2.json"
    m1.write_text('{"permissions": ["tabs"]}', encoding="utf-8")
    m2.write_text('{"permissions": ["cookies"]}', encoding="utf-8")

    expected_tabs = hashlib.sha256(b"tabs").hexdigest()
    expected_cookies = hashlib.sha256(b"cookies").hexdigest()

    with mock.patch.object(
        sys, "argv", ["permhash", "-t", "crx_manifest", "-p", str(m1)]
    ):
        cli.main()
    out_single = capsys.readouterr().out.strip().splitlines()
    assert out_single == [expected_tabs]

    with mock.patch.object(
        sys, "argv", ["permhash", "-t", "crx_manifest", "-p", str(tmp_path)]
    ):
        cli.main()
    out_dir = capsys.readouterr().out.strip().splitlines()
    assert len(out_dir) == 2
    assert set(out_dir) == {expected_tabs, expected_cookies}
