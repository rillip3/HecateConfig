'''Hecate: a small utility to move config files safely.'''

import os
import json
from typing import Container
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
        passed. As of this writing (2021-04-23) Rackspace public cloud supports
        v2 of auth
        '''
        authURL = self.getConfig('auth_url')
        authHeaders = {"Content-type": "application/json"}
        data = {"auth": {"RAX-KSKEY:apiKeyCredentials": {
            "username": self.getConfig('user'),
            "apiKey": self.getConfig('api_key')}}}
        token = requests.post(authURL, json=data, headers=authHeaders)
        token.raise_for_status()
        toReturn = token.json().get('access', {}).get('token', {}).get('id')
        if headers:
            headers['X-Auth-Token'] = toReturn
        return toReturn

    def _openstack_auth_helper(self, headers={}):
        '''
        This method generates an auth token for generic Openstack.
        It will update the headers with the X-Auth-Token header pre-filled
        if they are passed. As of this writing (2021-04-23) Openstack is on
        auth v3.
        '''
        authURL = self.getConfig('auth_url')
        authHeaders = {"Content-type": "application/json"}
        data = {"auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": self.getConfig('user'),
                                "domain": {
                                    "name": "Default"
                                },
                                "password": self.getConfig('api_key')
                            }
                        }
                    }
               }
        }
        token = requests.post(authURL, json=data, headers=authHeaders)
        token.raise_for_status()
        toReturn = token.headers.get('X-Subject-Token')
        if headers:
            headers['X-Auth-Token'] = toReturn
        return toReturn

    def _openstack_upload_helper(self, filename, headers, container= None):
        '''This method uploads files to Rackspace Openstack.
        It will automatically make the specified container for you if it does
        not exist.
        '''
        data = ''
        with open(filename, 'rb') as message:
            data = message.read()
        url = self.getConfig('url')
        if container is None:
            container = self.getConfig('container')
        # create the container if it doesn't exist
        container_results = ''
        try:
            container_results = requests.put(url + '/' + container,
                                             headers=headers)
        except Exception as e:
            raise ValueError('Could not create container: %s' % str(e))
        try:
            container_results.raise_for_status()
        except Exception:
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

    def _openstack_download_helper(self, filename, headers, container=None):
        '''This method downloads files to Rackspace Openstack.'''
        url = self.getConfig('url')
        if container is None:
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

    def _openstack_remove_helper(self, filename, headers, container=None):
        '''This method remove files from Rackspace Openstack.'''
        url = self.getConfig('url')
        if container is None:
            container = self.getConfig('container')
        results = requests.delete(url + '/' + container + '/' + filename,
                               headers=headers)
        if results.status_code != 204:
            raise ValueError('Got an unexpected return during upload:'
                             ' %s. Code was %s' % (results.text,
                                                   results.status_code))
        return 'Success'

    def _openstack_conatiner_helper(self, container, headers, remove=False):
        '''This method creates and removes container from Rackspace Openstack.'''
        url = self.getConfig('url')
        if remove:
            results = requests.delete(url + '/' + container,
                                headers=headers)
            if results.status_code not in [201, 202]:
                raise ValueError('Got an unexpected return during container deletion:'
                                ' %s. Code was %s' % (results.text,
                                                    results.status_code))
        else:
            results = requests.put(url + '/' + container,
                                headers=headers)
            if results.status_code not in [201, 202]:
                raise ValueError('Got an unexpected return during container creation:'
                                ' %s. Code was %s' % (results.text,
                                                    results.status_code))
        return 'Success'

    def _rs_openstack_remove_helper(self, filename, headers, container=None):
        # only auth is not reverse compatible with openstack v3 vs v2
        return self._openstack_remove_helper(filename, headers, container)

    def _rs_openstack_download_helper(self, filename, headers, container=None):
        # only auth is not reverse compatible with openstack v3 vs v2
        return self._openstack_download_helper(filename, headers, container)

    def _rs_openstack_upload_helper(self, filename, headers, container=None):
        # only auth is not reverse compatible with openstack v3 vs v2
        return self._openstack_upload_helper(filename, headers, container)

    def cloud_file(self, filename, download=False, container=None):
        '''This method quarterbacks cloud operations. It gets a helper to
        gather the auth token and then either calls the upload or download
        helper.'''
        toReturn = ''
        provider = self.getConfig('provider')
        headers = self.getConfig('headers')
        if provider.lower() == 'rackspace':
            # supports Rackspace Openstack on auth v2
            self._rs_openstack_auth_helper(headers)
            if download:
                toReturn = self._rs_openstack_download_helper(filename,
                                                              headers, container)
            else:
                toReturn = self._rs_openstack_upload_helper(filename, headers, container)
        elif provider.lower() == 'openstack':
            self._openstack_auth_helper(headers)
            if download:
                toReturn = self._openstack_download_helper(filename,
                                                           headers, container)
            else:
                toReturn = self._openstack_upload_helper(filename, headers, container)
            # supports Openstack on auth v3
        else:
            # the developer is using Rackspace Openstack; if others wish to
            # write their own authentication helpers, pull requests are
            # accepted.
            raise NotImplementedError('The provider'
                                      ' %s is not available.' % provider)
        return toReturn

    def cloud_file_remove(self, filename, container=None):
        '''This method quarterbacks cloud operations. It gets a helper to
        gather the auth token and then calls remove helper.'''
        toReturn = ''
        provider = self.getConfig('provider')
        headers = self.getConfig('headers')
        if provider.lower() == 'rackspace':
            # supports Rackspace Openstack on auth v2
            self._rs_openstack_auth_helper(headers)
            toReturn = self._rs_openstack_remove_helper(filename, headers, container=None)
        elif provider.lower() == 'openstack':
            toReturn = self._openstack_remove_helper(filename, headers, container=None)
            # supports Openstack on auth v3
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
        # python3 read is already bytes, python2 read string and must be
        # converted
        if type(key) == str:
            try:
                key = key.encode()
            except Exception:
                raise ValueError('Could not turn key into bytes!')
        # we have a file and a key, let's decrypt
        fernet = None
        try:
            fernet = Fernet(key)
        except TypeError:
            raise ValueError('Unable to create key from given value;'
                             ' ensure the key has not been truncated')
        decrypted = fernet.decrypt(message)
        toWriteFilename = filename
        if not inplace:
            toWriteFilename = filename + '_decrypted'
        with open(toWriteFilename, 'wb') as toWrite:
            toWrite.write(decrypted)
        return 'Decrypted file written to %s.' % toWriteFilename

    def encrypt_file(self, filename, inplace, keyfile=None):
        '''This method decrypts the given file. If inplace is used, the file is
        destructively modified to have the unencrypted output.
        The encryption key is written to disk as hecate_key.
        The key file is always destructively modified to have the just-used
        encryption key.'''
        newKey = False
        key = self.key  # get previous key if available
        if not key:  # no previous key available
            if keyfile == '':  # keyfile was sent by args, but is empty
                key = self.getConfig('encrypt_key')
                if not key:
                    raise ValueError('-k, --key was specified without a file '
                                     'but hecate_encrypt_key environment '
                                     'variable was not set. Either specify '
                                     'a file, set the variable, or remove '
                                     'the option to use an auto-generated key')
            elif keyfile:  # a keyfile was specified and is not empty
                with open(keyfile, 'rb') as toRead:
                    key = toRead.read()
            else:  # a keyfile was not specified, make one
                newKey = True
                key = Fernet.generate_key()
            self.key = key  # set the key for future runs
        message = ''
        with open(filename, 'rb') as toRead:
            message = toRead.read()
        if not message:
            raise ValueError('Error: file named %s was empty.' % filename)
        # generate a key for encryption and decryption
        fernet = None
        try:
            fernet = Fernet(key)
        except TypeError:
            raise ValueError('Unable to create key from given value;'
                             ' ensure the key has not been truncated')
        encMessage = fernet.encrypt(message)
        toWriteFilename = filename
        if not inplace:
            toWriteFilename = filename + '_encrypted'
        with open(toWriteFilename, 'wb') as toWrite:
            toWrite.write(encMessage)
        toReturn = 'Encrypted file written to %s. ' % toWriteFilename
        if newKey:
            with open('hecate_key', 'wb') as toWrite:
                toWrite.write(key)
            toReturn = toReturn + 'Encryption key written to hecate_key. '\
                                  'KEEP IT SECRET! KEEP IT SAFE!'
        return toReturn

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

    def cloud_container_add(self, container_name):
        '''Method to create container in cloud.'''
        toReturn = ''
        provider = self.getConfig('provider')
        headers = self.getConfig('headers')
        if provider.lower() == 'rackspace':
            # supports Rackspace Openstack on auth v2
            self._rs_openstack_auth_helper(headers)
            toReturn = self._openstack_conatiner_helper(container_name, headers)
        elif provider.lower() == 'openstack':
            self._openstack_auth_helper(headers)
            toReturn = self._openstack_conatiner_helper(container_name, headers)
            # supports Openstack on auth v3
        else:
            # the developer is using Rackspace Openstack; if others wish to
            # write their own authentication helpers, pull requests are
            # accepted.
            raise NotImplementedError('The provider'
                                      ' %s is not available.' % provider)
        return toReturn


    def cloud_container_remove(self, container_name):
        '''Method to remove container in cloud.'''
        toReturn = ''
        provider = self.getConfig('provider')
        headers = self.getConfig('headers')
        if provider.lower() == 'rackspace':
            # supports Rackspace Openstack on auth v2
            self._rs_openstack_auth_helper(headers)
            toReturn = self._openstack_conatiner_helper(container_name, headers,
                remove=True)
        elif provider.lower() == 'openstack':
            self._openstack_auth_helper(headers)
            toReturn = self._openstack_conatiner_helper(container_name, headers,
                remove=True)
            # supports Openstack on auth v3
        else:
            # the developer is using Rackspace Openstack; if others wish to
            # write their own authentication helpers, pull requests are
            # accepted.
            raise NotImplementedError('The provider'
                                      ' %s is not available.' % provider)
        return toReturn

def process(arguments):
    '''Takes the command line arguments and calls the appropriate Hecate
     methods.'''
    if not (arguments.file or arguments.remove or arguments.newContainer
            or arguments.removeContainer):
        return 'Please choose at least one option.'
    runner = Hecate(arguments.config)
    result = {}
    skipFiles = []
    if arguments.get:
        result['download'] = {}
    if arguments.encrypt:
        result['encrypt'] = {}
    if arguments.upload:
        result['upload'] = {}
    if arguments.decrypt:
        result['decrypt'] = {}
    if arguments.remove:
        result['remove'] = {}
    if arguments.newContainer:
        result['newContainer'] = {}
    if arguments.removeContainer:
        result['removeContainer'] = {}
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
    # Remove and create new container were added later and are a side stream
    # new container has to come before upload, or you'll upload to a container
    # that doesn't exist. Remove container is a deletion, and should be done last.
    if arguments.newContainer:
        try:
            if arguments.newContainer not in skipFiles:
                result['newContainer'][arguments.newContainer] = runner.cloud_container_add(
                    arguments.newContainer)
            else:
                result['newContainer'][arguments.newContainer] = 'Skipped due to previous error.'
        except Exception as e:
            result['newContainer'][arguments.newContainer] = 'Error: %s' % str(e)
            skipFiles.append(arguments.newContainer)
    if arguments.file:
        for entry in arguments.file[0]:
            if arguments.get:
                try:
                    result['download'][entry] = runner.cloud_file(entry,
                                                                download=True)
                except Exception as e:
                    result['download'][entry] = 'Error: %s' % str(e)
                    skipFiles.append(entry)
            if arguments.encrypt:
                # if they specified a key, send it
                keyfile = None  # if they did not sent -k, send None
                if arguments.key and arguments.key != '':
                    # they specified -k and gave the filename
                    keyfile = arguments.key
                elif arguments.key == '':
                    # they specified -k but did not gice a filename
                    keyfile = ''
                try:
                    if entry not in skipFiles:
                        result['encrypt'][entry] = runner.encrypt_file(
                            entry, arguments.inplace, keyfile=keyfile)
                    else:
                        result['encrypt'][entry] = 'Skipped due to previous error.'
                except Exception as e:
                    result['encrypt'][entry] = 'Error: %s' % str(e)
                    skipFiles.append(entry)
            if arguments.upload:
                try:
                    if entry not in skipFiles:
                        if arguments.inplace or not result.get('encrypt'):
                            result['upload'][entry] = runner.cloud_file(entry,
                                container = arguments.specifyContainer)
                        # they have not specified inplace but did specify encrypt
                        else:
                            name = entry + '_encrypted'
                            result['upload'][name] = runner.cloud_file(name,
                                container = arguments.specifyContainer)
                    else:  # skip the file
                        result['upload'][entry] = 'Skipped due to previous error.'
                except Exception as e:
                    result['upload'][entry] = 'Error: %s' % str(e)
                    skipFiles.append(entry)
            if arguments.decrypt:
                try:
                    if entry not in skipFiles:
                        result['decrypt'][entry] = runner.decrypt_file(
                            entry, arguments.key, arguments.inplace)
                    else:
                        result['encrypt'][entry] = 'Skipped due to previous error.'
                except Exception as e:
                    result['decrypt'][entry] = 'Error: %s' % str(e)
                    skipFiles.append(entry)
    if arguments.remove:
        for entry in arguments.remove[0]:
            try:
                if entry not in skipFiles:
                    result['remove'][entry] = runner.cloud_file_remove(
                        entry, container = arguments.specifyContainer)
                else:
                    result['remove'][entry] = 'Skipped due to previous error.'
            except Exception as e:
                result['remove'][entry] = 'Error: %s' % str(e)
                skipFiles.append(entry)
    if arguments.removeContainer:
        try:
            if arguments.removeContainer not in skipFiles:
                result['removeContainer'][arguments.removeContainer] = runner.cloud_container_remove(
                    arguments.removeContainer)
            else:
                result['removeContainer'][arguments.removeContainer] = 'Skipped due to previous error.'
        except Exception as e:
            result['removeContainer'][arguments.removeContainer] = 'Error: %s' % str(e)
            skipFiles.append(arguments.removeContainer)
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
                          help='Flag; download the file.')
    parser.add_argument('-f', '--file', action='append', nargs='+',
                        help='File paths to action on.')
    parser.add_argument('-r', '--remove', action='append', nargs='+',
                        help='File paths to remove.')
    # const means that if -k is passed with no value, we can detect it
    parser.add_argument('-k', '--key',
                        help='The key to use during encryption or decryption. '
                             'If specified without a value, environment '
                             ' variables will be checked. If not specified '
                             'for encryption, a new key will be generated '
                             'and saved to disk. Required for decryption.',
                        nargs='?', const='')
    parser.add_argument('-i', '--inplace', action='store_true',
                        help="Flag; Encrypt or decrypt the file in-place."
                             "self implies the file's contents are "
                             "destructively modified.")
    parser.add_argument('-c', '--config',
                        help='Json credentials file required for uploads '
                             'and downloads.')
    parser.add_argument('-nc', '--newContainer',
                        help='Creates new container for your files.')
    parser.add_argument('-rc', '--removeContainer',
                        help='Delete given container from Storage.')
    parser.add_argument('-sc', '--specifyContainer',
                        help='Spicify container for files.')
    arguments = parser.parse_args()
    pprint(process(arguments))
