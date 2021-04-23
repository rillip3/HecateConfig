# Hecate
A python utility for safely conveying config files where they need to be.

Hecate will encrypt files, upload files to cloud files, and decrypt files.
The typical use pattern is to run Hecate with encrypt and upload options
enabled in one location, then use the download/decrypt option in another.

It is recommend to use the -i or --inplace option when chaining actions.
The order of operations is:

Download, Encrypt, Decrypt, Upload.

Download/upload are mutually exlcusive. Encrypt/decrypt are mutually
exclusive.  As such, if you use the -i option, the file you upload will
always match your local file. With download, the final file will be in the
state you specified. If you chose not to use -i, be aware that an
unencrypted file will be uploaded, and an encrypted version left on your
disk with the name filename_encrypted.

Note that using -i will destructively modify the file. If you have files
you do not wish to risk destructively modifying, you can run without -i and
the files will be saved to filename_encrypted or filename_decrypted,
respectively.

When encrypting, the key is saved to hecate_key. The key file is always
destructively modified! KEEP YOUR KEYS SECRET, KEEP YOUR KEYS SAFE!
These are Fernet symetrical keys, so it is critical to keep the keys safe.

When encrypting or decrypting multiple files, one keyfile is used for all of
them.

You may chose to use the -c, --config option to make management easier.
An example has been given in this reposity in config.json.sample.
To facilitate keeping secret keys secret, you may include or omit as much
as you want from the config file. If a needed value is not found in the config
file, Hecate will automatically look in your local environment variables for
'hecate_keyname', where keyname is the name of whatever config value is
needed. For example, you might chose not to put api_key in the config file,
in which case you would want to set the environment variable hecate_api_key
to your provider's API key.

At this time, only Rackspace Openstack has been set up as an upload/download
provider. Pull requests are accepted for other providers. Please provide
example output from runs on your provider at the time of making the pull
request in both Python 2.7.16 and Python 3.x.

Hecate has been tested on Python 2.7.16 and Python 3.7.3, but should run
on any Python3 version without isssue.

# Requirements
Hecate only requires the requests library. You can run

pip install -r requirements.txt

To install it on most systems.

# Examples

Encrypting a file and uploading it:
python3 hecate.py -e -u -f testfile -c config.json

Decrypting multiple files after downloading:
python3 hecate.py -d -g -f testfile1 testfile2 -c config.json



# Usage
usage: hecate.py [-h] [-e | -d] [-u | -g] [-f FILE [FILE ...]] [-k KEY] [-i]
                 [-c CONFIG]

A utility to encrypt/decrypt/upload files safely

optional arguments:
  -h, --help            show this help message and exit
  -e, --encrypt         Flag; encrypt the file.
  -d, --decrypt         Flag; decrypt the file.
  -u, --upload          Flag; upload the file.
  -g, --get             Optional; download the file.
  -f FILE [FILE ...], --file FILE [FILE ...]
                        File paths to action on.
  -k KEY, --key KEY     Key required for decrypting.
  -i, --inplace         Flag; Encrypt or decrypt the file in-place.self
                        implies the file's contents are destructively
                        modified.
  -c CONFIG, --config CONFIG
                        Json credentials file required for uploadsand
                        downloads.

# LICENSE

Copyright 2021 Philip Eatherington

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
