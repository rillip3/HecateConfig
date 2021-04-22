import json
import requests
import argparse
from pprint import pprint
from cryptography.fernet import Fernet


def process(arguments):
    if not arguments.file:
        return 'No files chosen, use -f, --file to specify filenames (space '\
               'delineated).'
    if arguments.upload and not arguments.config:
        return 'No config file provided with upload credentials, '\
               'use -c, --config to specify the json file'
    if arguments.decrypt and not arguments.key:
        return 'No key file provided to decrypt the file, '\
               'use -k, --key to specify the encryption key file'
    result = {}
    if arguments.encrypt:
        result['encrypt'] = {}
    if arguments.upload:
        result['upload'] = {}
    if arguments.get:
        result['download'] = {}
    if arguments.decrypt:
        result['decrypt'] = {}
    # argparse returns a list of lists for files, filenames are
    # [ [text1], [text2] ]
    # so slice the first (and only) value out of entry
    # Philosophy on order of operations
    # Uploaded files should look just like the local copy.
    # If multiple actions are requested, do everything before the upload, that
    # way the file is uploaded just the way the user asked.
    # If there are multiple actions on a download, the actions should be
    # performed on the downloaded file.
    # Thus, the order of operations is download, encrypt/decrypt, upload
    for entry in arguments.file:
        if arguments.get:
            try:
                result['download'][entry[0]] = cloud_file(entry[0],
                                                          arguments.config,
                                                          download=True)
            except Exception as e:
                result['download'][entry[0]] = 'Error: %s' % str(e)
        if arguments.encrypt:
            try:
                result['encrypt'][entry[0]] = encrypt_file(entry[0],
                                                           arguments.inplace)
            except Exception as e:
                result['encrypt'][entry[0]] = 'Error: %s' % str(e)
        if arguments.upload:
            try:
                result['upload'][entry[0]] = cloud_file(entry[0],
                                                        arguments.config)
            except Exception as e:
                result['upload'][entry[0]] = 'Error: %s' % str(e)
        if arguments.decrypt:
            try:
                result['decrypt'][entry[0]] = decrypt_file(entry[0],
                                                           arguments.key,
                                                           arguments.config)
            except Exception as e:
                result['decrypt'][entry[0]] = 'Error: %s' % str(e)
    return result


def _rs_openstack_auth_helper(auth, headers={}):
    authURL = auth.get('url')
    authHeaders = {"Content-type": "application/json"}
    data = {"auth": {"RAX-KSKEY:apiKeyCredentials": {
        "username": auth.get('user'), "apiKey": auth.get('key')}}}
    token = requests.post(authURL, json=data, headers=authHeaders)
    toReturn = token.json().get('access', {}).get('token', {}).get('id')
    if headers:
        headers['X-Auth-Token'] = toReturn
    return toReturn


def _rs_openstack_upload_helper(filename, headers, config):
    data = ''
    with open(filename, 'r') as message:
        data = message.read()
    url = config.get('url')
    container = config.get('container')
    results = requests.put(url + '/' + container + '/' + filename,
                           data=data,
                           headers=headers)
    if results.status_code != 201:
        raise ValueError('Got an unexpected return during upload: %s. '
                         'Code was %s' % (results.text,  results.status_code))
    return 'Success'


def _rs_openstack_download_helper(filename, headers, config):
    url = config.get('url')
    container = config.get('container')
    results = requests.get(url + '/' + container + '/' + filename,
                           headers=headers)
    if results.status_code != 200:
        raise ValueError('Got an unexpected return during upload: %s. '
                         'Code was %s' % (results.text,  results.status_code))
    with open(filename, 'w') as toWrite:
        toWrite.write(results.content)
    return 'Success'


def cloud_file(filename, config, auth=False, download=False):
    toReturn = ''
    configs = json.loads(open(config, 'r').read())
    if not configs:
        raise ValueError('Got empty config file.')
    provider = configs.get('provider')
    if provider.lower() == 'rackspace':
        headers = configs.get('headers')
        auth = configs.get('auth', {})
        _rs_openstack_auth_helper(auth, headers)
        if download:
            toReturn = _rs_openstack_download_helper(filename, headers,
                                                     configs)
        else:
            toReturn = _rs_openstack_upload_helper(filename, headers, configs)
    else:
        # the developer is using Rackspace Openstack; if others wish to write
        # their own authentication helpers, pull requests are accepted.
        raise ValueError('Automated auth for provider '
                         '%s is not available.' % provider)
    return toReturn


def decrypt_file(filename, keyfile, inplace):
    message = ''
    key = ''
    with open(filename, 'r') as toRead:
        message = toRead.read()
    if not message:
        raise ValueError('Error: file named %s was empty.' % filename)
    with open(keyfile, 'r') as toRead:
        key = toRead.read()
    if not key:
        raise ValueError('Error: file named %s was empty.' % filename)
    # we have a file and a key, let's decrypt
    fernet = Fernet(key)
    decrypted = fernet.decrypt(message).decode()
    toWriteFilename = filename
    if not inplace:
        toWriteFilename = filename + '_decrypted'
    with open(toWriteFilename, 'w') as toWrite:
        toWrite.write(decrypted)
    return 'Decrypted file written to %s.' % toWriteFilename


def encrypt_file(filename, inplace):
    message = ''
    with open(filename, 'r') as toRead:
        message = toRead.read()
    if not message:
        raise ValueError('Error: file named %s was empty.' % filename)
    # generate a key for encryptio and decryption
    key = Fernet.generate_key()
    # Instance the Fernet class with the key
    fernet = Fernet(key)
    # then use the Fernet class instance
    # to encrypt the string string must must
    # be encoded to byte string before encryption
    encMessage = fernet.encrypt(message.encode())
    toWriteFilename = filename
    if not inplace:
        toWriteFilename = filename + '_encrypted'
    with open(toWriteFilename, 'w') as toWrite:
        toWrite.write(encMessage)
    with open(toWriteFilename + '_key', 'w') as toWrite:
        toWrite.write(key)
    return 'Encrypted file written to %s.'\
           'Encryption key written to %s.'\
           ' KEEP IT SECRET! KEEP IT SAFE!' % (toWriteFilename,
                                               toWriteFilename + '_key')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='A utility to encrypt/decrypt/upload config files safely')
    enOrDe = parser.add_mutually_exclusive_group()
    enOrDe.add_argument('-e', '--encrypt', action='store_true',
                        help='Flag; encrypt the file.')
    enOrDe.add_argument('-d', '--decrypt', action='store_true',
                        help='Flag; decrypt the file.')
    upOrDown = parser.add_mutually_exclusive_group()
    upOrDown.add_argument('-u', '--upload', action='store_true',
                          help='Flag; upload the file.')
    upOrDown.add_argument('-g', '--get', action='store_true',
                          help='Optional; download the file.')
    parser.add_argument('-f', '--file', action='append', nargs='+',
                        help='File paths to action on.')
    parser.add_argument('-k', '--key', help='Key required for decrypting.')
    parser.add_argument('-i', '--inplace', action='store_true',
                        help="Flag; Encrypt or decrypt the file in-place."
                             "This implies the file's contents are "
                             "destructively modified.")
    parser.add_argument('-c', '--config',
                        help='Json credentials file required for uploads'
                             'and downloads.')
    arguments = parser.parse_args()
    pprint(process(arguments))
