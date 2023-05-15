<img src="https://github.com/google/permhash/blob/59d2c35765cf3b97ce310a3708e1cc8aa839a5a5/docs/images/permhash.jpg" align="center" width="20%" height="20%">

[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/permhash)](https://pypi.org/project/permhash)
[![Last release](https://img.shields.io/github/v/release/google/permhash)](https://github.com/google/permhash/releases)
[![Downloads](https://img.shields.io/github/downloads/google/permhash/total)](https://github.com/google/permhash/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE.txt)

Permhash is an extensible framework to hash the declared permissions applied to Chromium-based browser extensions and APKs allowing for clustering, hunting, and pivoting similar to import hashing and rich header hashing.

Permhash is currently capable of running on four types of files, but is extensible beyond this:
1. An Android Package (APK) file.
2. A Chromium-based Extension file (CRX).
3. An AXML Android Manifest file found at the root directory within APKs.
4. A JSON Extension Manifest from a Chromium-based extension.


# Download and Usage

Install the permhash library
```
pip install permhash
```

## Library Use

Import permhash
```
from permhash import functions as permhash
```

Use permhash
```
# The path variable should be the full path to the file you wish to use to calculate the permhash.

# Calculate the permhash for a CRX
ph = permhash.permhash_crx(path)

# Calculate the permhash for a CRX manifest
ph = permhash.permhash_crx_manifest(path)

# Calculate the permhash for an APK
ph = permhash.permhash_apk(path)

# Calculate the permhash for an APK manifest
ph = permhash.permhash_apk_manifest(path)
```

### Example

An example of calculating permhash in bulk.

```
import csv
import os
from permhash import functions as permhash


def bulk_permhash_crx_manifest(path, output):
    """
    Computes the permhash from a directory of CRX manifests
    Outputs the results in a csv passed as input

    :param path: The targeted directory
    :type path: string
    :param output:
    :type path: string

    """
    with open(output, mode="w", encoding="utf-8") as results:
        out_writer = csv.writer(
            results, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
        )
        out_writer.writerow(["filename", "permhash"])
        for filename in os.listdir(path):
            if path.endswith("/"):
                full_path = path + filename
            else:
                full_path = path + "/" + filename
            calculated_permhash = permhash.permhash_crx_manifest(full_path)
            if calculated_permhash:
                out_writer.writerow([filename, calculated_permhash])

```
## Commandline Use

Permhash can also be used as a commandline tool. Provide the full path to the file to calculate the permhash in the --path/-p switch and the type of file being analyzed in the --type/-t switch. The command will output the permhash or False if it is an invalid file.

```
permhash --type crx --path '[PATH TO CRX File]'
permhash --type crx_manifest --path '[PATH TO CRX Manifest File]'
permhash --type apk --path '[PATH TO APK File]'
permhash --type apk_manifest --path '[PATH TO APK Manifest Files]'
```


# Further Information
## Permhash
[Permhash Blog](https://www.mandiant.com/resources/blog/)

## Discussion
The [Permhash Google Group](https://groups.google.com/g/permhash) can be used to facilitate discussion.

# Disclaimer
This is not an officially supported Google product.
