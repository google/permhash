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

APK_MIMETYPES = [
    "application/zip",
    "application/java-archive",
    "application/vnd.android.package-archive",
]
CRX_MANIFEST_MIMETYPES = ["text/plain", "application/json"]
CRX_MIMETYPES = ["application/x-chrome-extension", "application/zip"]
APK_MANIFEST_MIMETYPES = ["application/octet-stream"]
IPA_MIMETYPES = [
    "application/x-ios-app",
    "application/zip",
    "application/vnd.debian.binary-package",
]
MACHO_MIMETYPES = ["application/x-mach-binary"]