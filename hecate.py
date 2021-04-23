'''Hecate: a small utility to move config files safely.'''

import os
import json
import requests
import argparse
from pprint import pprint
from cryptography.fernet import Fernet


class Hecate:
    def __init__(self, configFileName=None):
        '''The config file name is optional; if it is not passed, all config
        settings will attempt to be read from environment variables prefaced
        with hecate_.'''
        self.config = None
        self.key = None
        if configFileName:
            try:
                self.config = json.loads(open(configFileName, 'r').read())
            except Exception as e:
                raise ValueError('Unable to read config file: %s' % str(e))

    def _rs_openstack_auth_helper(self, headers={}):
        '''
        This method generates an auth token for Rackspace Openstack. It will
        update the headers with the X-Auth-Token header pre-filled if they are
        passed.
        '''
        authURL = self.getConfig('auth_url')
        authHeaders = {"Content-type": "application/json"}
        data = {"auth": {"RAX-KSKEY:apiKeyCredentials": {
            "username": self.getConfig('user'),
            "apiKey": self.getConfig('api_key')}}}
        token = requests.post(authURL, json=data, headers=authHeaders)
        toReturn = token.json().get('access', {}).get('token', {}).get('id')
        if headers:
            headers['X-Auth-Token'] = toReturn
        return toReturn

    def _rs_openstack_upload_helper(self, filename, headers):
        '''This method uploads files to Rackspace Openstack.
        It will automatically make the specified container for you if it does
        not exist.
        '''
        data = ''
        with open(filename, 'r') as message:
            data = message.read()
        url = self.getConfig('url')
        container = self.getConfig('container')
        # create the container if it doesn't exist
        container_results = ''
        try:
            container_results = requests.put(url + '/' + container,
                                             headers=headers)
        except Exception as e:
            raise ValueError('Could not create container: %s' % str(e))
        if container_results.raise_for_status():
            raise ValueError('Got an unexpected code when creating container:'
                             ' %s %s' % (container_results.status_code,
                                         container_results.text))
        results = requests.put(url + '/' + container + '/' + filename,
                               data=data,
                               headers=headers)
        if results.status_code != 201:
            raise ValueError('Got an unexpected return during upload: '
                             ' %s. Code was %s' % (results.text,
                                                   results.status_code))
        return 'Success'

    def _rs_openstack_download_helper(self, filename, headers):
        '''This method downloads files to Rackspace Openstack.'''
        url = self.getConfig('url')
        container = self.getConfig('container')
        results = requests.get(url + '/' + container + '/' + filename,
                               headers=headers)
        if results.status_code != 200:
            raise ValueError('Got an unexpected return during upload:'
                             ' %s. Code was %s' % (results.text,
                                                   results.status_code))
        with open(filename, 'wb') as toWrite:
            toWrite.write(results.content)
        return 'Success'

    def cloud_file(self, filename, download=False):
        '''This method quarterbacks cloud operations. It gets a helper to
        gather the auth token and then either calls the upload or download
        helper.'''
        toReturn = ''
        provider = self.getConfig('provider')
        if provider.lower() == 'rackspace':
            headers = self.getConfig('headers')
            self._rs_openstack_auth_helper(headers)
            if download:
                toReturn = self._rs_openstack_download_helper(filename,
                                                              headers)
            else:
                toReturn = self._rs_openstack_upload_helper(filename, headers)
        else:
            # the developer is using Rackspace Openstack; if others wish to
            # write their own authentication helpers, pull requests are
            # accepted.
            raise NotImplementedError('The provider'
                                      ' %s is not available.' % provider)
        return toReturn

    def decrypt_file(self, filename, keyfile, inplace):
        '''This method decrypts the given file. If inplace is used, the file is
         destructively modified to have the unencrypted output.'''
        # everything is converted to bytes if a string so we can use one write
        # method across python2 and 3
        message = ''
        key = ''
        with open(filename, 'rb') as toRead:
            message = toRead.read()
        if not message:
            raise ValueError('Error: file named %s was empty.' % filename)
        if keyfile:
            with open(keyfile, 'rb') as toRead:
                key = toRead.read()
        else:
            key = os.getenv('hecate_decrypt_key')
        if not key:
            raise ValueError('No key specified; either use -k, --key or set '
                             'the environment variable hecate_decrypt_key')
        try:
            key = bytes(key, 'utf-8')
        except Exception:
            try:
                key = key.encode()
                # python 2 work around; bytes() == str() in python 2
            except Exception:
                raise ValueError('Could not turn key into bytes!')
        # we have a file and a key, let's decrypt
        fernet = Fernet(key)
        decrypted = fernet.decrypt(message)
        toWriteFilename = filename
        if not inplace:
            toWriteFilename = filename + '_decrypted'
        with open(toWriteFilename, 'wb') as toWrite:
            toWrite.write(decrypted)
        return 'Decrypted file written to %s.' % toWriteFilename

    def encrypt_file(self, filename, inplace):
        '''This method decrypts the given file. If inplace is used, the file is
        destructively modified to have the unencrypted output.
        The encryption key is written to disk as hecate_key.
        The key file is always destructively modified to have the just-used
        encryption key.'''
        # bytes are used for everything so that one write call can be used
        # between python 2 and 3
        message = ''
        with open(filename, 'rb') as toRead:
            message = toRead.read()
        if not message:
            raise ValueError('Error: file named %s was empty.' % filename)
        # generate a key for encryption and decryption
        key = self.key
        if not key:
            key = Fernet.generate_key()
            self.key = key
        fernet = Fernet(key)
        encMessage = fernet.encrypt(message)
        toWriteFilename = filename
        if not inplace:
            toWriteFilename = filename + '_encrypted'
        with open(toWriteFilename, 'wb') as toWrite:
            toWrite.write(encMessage)
        with open('hecate_key', 'wb') as toWrite:
            toWrite.write(key)
        return 'Encrypted file written to %s. '\
            'Encryption key written to hecate_key. '\
            'KEEP IT SECRET! KEEP IT SAFE!' % toWriteFilename

    def getConfig(self, key):
        '''This helper method handles reading config items from either the
        config file or the environment variables as needed.'''
        value = ''
        if self.config:  # if we haven't read the config file yet
            value = self.config.get(key)
        if not value:
            value = os.getenv('hecate_' + key)
            if not value:
                raise ValueError('Could not find %s in config file or '
                                 'environment variables. Either update the '
                                 'config file, or set hecate_%s' % (key, key))
        return value


def process(arguments):
    '''Takes the command line arguments and calls the appropriate Hecate
     methods.'''
    if not arguments.file:
        return 'No files chosen, use -f, --file to specify filenames (space '\
               'delineated).'
    runner = Hecate(arguments.config)
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
    # [ [text1, text2] ]
    # so slice the first (and only) value out of entry
    # Philosophy on order of operations
    # Uploaded files should look just like the local copy.
    # If multiple actions are requested, do everything before the upload, that
    # way the file is uploaded just the way the user asked.
    # If there are multiple actions on a download, the actions should be
    # performed on the downloaded file.
    # Thus, the order of operations is download, encrypt/decrypt, upload
    for entry in arguments.file[0]:
        if arguments.get:
            try:
                result['download'][entry] = runner.cloud_file(entry,
                                                              download=True)
            except Exception as e:
                result['download'][entry] = 'Error: %s' % str(e)
        if arguments.encrypt:
            try:
                result['encrypt'][entry] = runner.encrypt_file(
                    entry, arguments.inplace)
            except Exception as e:
                result['encrypt'][entry] = 'Error: %s' % str(e)
        if arguments.upload:
            try:
                result['upload'][entry] = runner.cloud_file(entry)
            except Exception as e:
                result['upload'][entry] = 'Error: %s' % str(e)
        if arguments.decrypt:
            try:
                result['decrypt'][entry] = runner.decrypt_file(
                    entry, arguments.key, arguments.inplace)
            except Exception as e:
                result['decrypt'][entry] = 'Error: %s' % str(e)
    return result


if __name__ == "__main__":
    '''
    Just do some parsinng here, then hand off the parsed arguments to the
    process method to do the actual work.'''
    parser = argparse.ArgumentParser(
        description='A utility to encrypt/decrypt/upload files safely')
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
                             "self implies the file's contents are "
                             "destructively modified.")
    parser.add_argument('-c', '--config',
                        help='Json credentials file required for uploads'
                             'and downloads.')
    arguments = parser.parse_args()
    pprint(process(arguments))
