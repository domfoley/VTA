#!/usr/bin/python

import os
import sys
import time
import logging
import argparse
import threading
from kmip.pie.client import ProxyKmipClient, enums
from kmip.core.factories import attributes

logger = logging.getLogger()
if len(logger.handlers) == 0:
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(funcName)s:%(lineno)d: %(message)s')
    handler = logging.handlers.WatchedFileHandler('kmip.log')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

cert = '%s/vta.pem' % (os.getcwd())
cacert = '%s/cacert.pem' % (os.getcwd())
key = '%s/vtakey.key' % (os.getcwd())
print(cert, cacert)
config = {
    'hostname': '<IP ADDRESS OF KMS>',  # IP Address of Entrust KMS
    'port' : '5696',
    'cert' : cert,
    'ca': cacert,
    #'key': key,
    'ssl_version': 'PROTOCOL_SSLv23',
    'kmip_version': enums.KMIPVersion.KMIP_1_2
}
KEYFILE = 'keyfile.txt'
COUNT = 10
ASYM_KEYSIZE=1024  #Possible values: 1024, 2048, 4096
SYM_KEYSIZE=256  #Possible values: 128, 256

class KMIPKEK(object):

    def kmip_create_symkey(self, client=None):
        """
        Create KMIP Symmetric Key
        """
        try:
            if client is None:
                client = ProxyKmipClient(**config)
                client.open()
            uuid = client.create(enums.CryptographicAlgorithm.AES, SYM_KEYSIZE,
                                 operation_policy_name='default',
                                 cryptographic_usage_mask=[enums.CryptographicUsageMask.ENCRYPT,
                                                           enums.CryptographicUsageMask.ENCRYPT])
            #client.activate(uuid)
        except Exception as exc:
            print(exc)
            sys.exit(1)
        return uuid

    def kmip_create_asymkey(self, client=None):
        """
        Create KMIP Asymmetric key
        """

        try:
            if client is None:
                client = ProxyKmipClient(**config)
                client.open()
            uuid1, uuid2 = client.create_key_pair(
                            enums.CryptographicAlgorithm.RSA,
                            ASYM_KEYSIZE,
                            operation_policy_name='default',
                            public_usage_mask=[enums.CryptographicUsageMask.VERIFY],
                            private_usage_mask=[enums.CryptographicUsageMask.SIGN])
            #client.activate(uuid)
        except Exception as exc:
            #print (exc, uuid1, uuid2)
            print (exc)
            sys.exit(1)
        return uuid1, uuid2

    def kmip_fetch(self, uuid, client=None):
        """
        Fetch KMIP object
        """
        try:
            if client is None:
                client = ProxyKmipClient(**config)
                client.open()
            key = client.get(uuid)
            attr = client.get_attributes(uuid, ['Cryptographic Length'])
            print(attr)
        except Exception as exc:
            print (exc, uuid)
            sys.exit(1)
        return str(key)

    def kmip_destroy(self, guid, client=None):
        """
        Delete KMIP object
        """
        try:
            if client is None:
                client = ProxyKmipClient(**config)
                client.open()
            client.destroy(guid)
            print('Delete kmip guid: %s', guid)
        except Exception as exc:
            print (exc, guid)
            sys.exit(1)

    def kmip_locate(self, sym=True, offset=0, count = 10, client=None):
        try:
            if sym:
                attr = enums.ObjectType.SYMMETRIC_KEY
            else:
                attr = enums.ObjectType.PRIVATE_KEY
            print("Here")
            if client is None:
                client = ProxyKmipClient(**config)
                client.open()
            f = attributes.AttributeFactory()
            print("Here1")
            key = client.locate(
                        maximum_items=int(count),
#                        offset_items=int(offset),
                        attributes=[
                            f.create_attribute(
                                'x-NETAPP-ClusterId',
                                '50b7a51c-6f12-11e4-88de-123478563412'
                            ),
                            f.create_attribute(
                                'x-NETAPP-KeyType',
                                'AES'
                            ),
                            f.create_attribute(
                                'x-NETAPP-Product',
                                'Data ONTAP'
                            ),
                            f.create_attribute(
                                'x-NETAPP-VserverId',
                                '46'
                            ),
                        ]
                    )
        except Exception as exc:
            print (exc)
            sys.exit(1)
        print(key, len(key))

    def kmip_create_symkey500(self):
        """
        Create and write 500 Symmetric KMIP keys
        """
        try:
            client = ProxyKmipClient(**config)
            client.open()
            with open(KEYFILE, 'a') as f:
                for i in range(COUNT):
                    uuid = self.kmip_create_symkey(client)
                    key = self.kmip_fetch(uuid, client)
                    print ("%s: UUID:%s Key:%s" % (i, uuid, key))
                    f.write('%s %s\n' % (uuid, key))
        except Exception as exc:
            print (exc, uuid)
            sys.exit(1)

    def kmip_create_asymkey500(self):
        """
        Create and write 500 Symmetric KMIP keys
        """
        try:
            client = ProxyKmipClient(**config)
            client.open()
            with open(KEYFILE, 'a') as f:
                for i in range(COUNT):
                    uuid1, uuid2 = self.kmip_create_asymkey(client)
                    key1 = self.kmip_fetch(uuid1, client)
                    key2 = self.kmip_fetch(uuid2, client)
                    print ("%s: UUID:%s Key:%s\n" % (i, uuid1, key1))
                    print ("%s: UUID:%s Key:%s\n" % (i, uuid2, key2))
                    f.write('%s %s\n' % (uuid1, key1))
                    f.write('%s %s\n' % (uuid2, key2))
        except Exception as exc:
            print (exc, uuid1, uuid2)
            sys.exit(1)

    def kmip_fetch500(self):
        """
        Fetch and verify KMIP keys against value in file
        """
        try:
            client = ProxyKmipClient(**config)
            client.open()
            i = 0
            with open(KEYFILE, 'r') as fp:
                for line in fp:
                    arr = line.strip().split()
                    guid = arr[0]
                    key = str(client.get(guid))
                    if key == arr[1]:
                        print ("%s: Key match for GUID: %s" % (i, arr[0]))
                    else:
                        print ("%s: Invalid key. Key from KC : %s Key from file: %s" % (i, key, arr[1]))
                        raise RuntimeError('Invalid key for guid: %s' % guid)
                    i += 1
        except Exception as exc:
            print (exc, guid)
            sys.exit(1)

    def kmip_activate500(self):
        """
        Activate all keys
        """
        try:
            client = ProxyKmipClient(**config)
            client.open()
            i = 0
            with open(KEYFILE, 'r') as fp:
                for line in fp:
                    arr = line.strip().split()
                    guid = arr[0]
                    client.activate(guid)
                    print ("%s: Activated KMIP Guid: %s" % (i, guid))
                    i += 1
        except Exception as exc:
            print (exc, guid)
            sys.exit(1)

    def kmip_activate(self, guid):
        """
        Activate specific guid
        """
        try:
            client = ProxyKmipClient(**config)
            client.open()
            client.activate(guid)
            print ("Activated KMIP Guid: %s" % (guid))
        except Exception as exc:
            print (exc, guid)
            sys.exit(1)

    def kmip_revoke(self, guid):
        """
        Activate specific guid
        """
        try:
            client = ProxyKmipClient(**config)
            client.open()
            client.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION,
                            guid)
            print ("Revoked KMIP Guid: %s" % (guid))
        except Exception as exc:
            print (exc, guid)
            sys.exit(1)

    def kmip_revoke500(self):
        """
        Revoke all keys
        """
        try:
            client = ProxyKmipClient(**config)
            client.open()
            i = 0
            with open(KEYFILE, 'r') as fp:
                for line in fp:
                    arr = line.strip().split()
                    guid = arr[0]
                    client.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION,
                                  guid)
                    print ("%s: Revoked KMIP Guid: %s" % (i, guid))
                    i += 1
        except Exception as exc:
            print (exc, guid)
            sys.exit(1)

    def kmip_destroy500(self):
        """
        Destroy all keys
        """
        try:
            client = ProxyKmipClient(**config)
            client.open()
            i = 0
            with open(KEYFILE, 'r') as fp:
                for line in fp:
                    arr = line.strip().split()
                    guid = arr[0]
                    client.destroy(guid)
                    print ("%s: Deleted KMIP Guid: %s" % (i, guid))
                    i += 1
            os.unlink(KEYFILE)
        except Exception as exc:
            print (exc, guid)
            sys.exit(1)

    def __init__(self):
        parser = argparse.ArgumentParser(
                       description='KMIP commands',
                        usage='''kmip1.py <command> [<args>]
        The commands are:
                create_symkey       Create 256 bit Symmetric KMIP Key and return its guid
                create_asymkey      Create 256 bit Asymmetric KMIP Key and return its guids
                fetch               Fetch Key bits for specified guid
                activate            Activate KMIP object
                revoke              Revoke KMIP object
                destroy             Delete specific key
                kcinfo              Display KeyControl information
                create_symkey500    Create 500 Symmetric KMIP keys and write uuid and KMIP data to a file
                create_asymkey500   Create 500 Asymmetric KMIP keys and write uuid and KMIP data to a file
                verify500           Fetch key from KC and compare it against value in file
                activate500         Activate all keys
                revoke500           Revoke all 500 keys
                destroy500          Destroy all 500 keys
                sym_locate <offset> <count>  Locate symmetric key objects
                asym_locate <offset> <count> Locate asymmetric key objects
              ''')
        parser.add_argument('command', help='Subcommand to run')
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print ('Unrecognized command: %s' % (args.command))
            parser.print_help()
            exit(1)
        getattr(self, args.command)()

    def create_symkey(self):
        """
        Create KMIP object
        """
        uuid = self.kmip_create_symkey()
        print ("UUID: %s" % (uuid))

    def create_asymkey(self):
        """
        Create Asymmetric KMIP key
        """
        uuid1, uuid2 = self.kmip_create_asymkey()
        print ("UUID1: %s\nUUID2: %s" % (uuid1, uuid2))

    def fetch(self):
        """
        Fetch KMIP object
        """
        parser = argparse.ArgumentParser(
                    description='Fetch KMIP Key object for specified guid')
        parser.add_argument('uuid')
        args = parser.parse_args(sys.argv[2:])
        key = self.kmip_fetch(args.uuid)
        print ("Key: %s" % (key))

    def destroy(self):
        """
        Destroy kmip object
        """
        parser = argparse.ArgumentParser(
                    description='Delete KMIP Key object for specified guid')
        parser.add_argument('uuid')
        args = parser.parse_args(sys.argv[2:])
        self.kmip_destroy(args.uuid)

    def sym_locate(self):
        parser = argparse.ArgumentParser(
                    description='Skip offset items and return result')
        parser.add_argument('offset')
        parser.add_argument('count')
        args = parser.parse_args(sys.argv[2:])
        self.kmip_locate(True, args.offset, args.count)

    def asym_locate(self):
        parser = argparse.ArgumentParser(
                    description='Skip offset items and return result')
        parser.add_argument('offset')
        parser.add_argument('count')
        args = parser.parse_args(sys.argv[2:])
        print(args.count)
        self.kmip_locate(False, args.offset, args.count)

    def activate(self):
        """
        Activate all keys
        """
        parser = argparse.ArgumentParser(
                    description='Activate a KMIP Guid')
        parser.add_argument('guid')
        args = parser.parse_args(sys.argv[2:])
        self.kmip_activate(args.guid)

    def revoke(self):
        """
        Activate all keys
        """
        parser = argparse.ArgumentParser(
                    description='Revoke a KMIP Guid')
        parser.add_argument('guid')
        args = parser.parse_args(sys.argv[2:])
        self.kmip_revoke(args.guid)

    def activate500(self):
        """
        Activate all keys
        """
        self.kmip_activate500()

    def create_symkey500(self):
        """
        Create 500 KMIP keys and write uuid and KMIP data to a file
        """
        self.kmip_create_symkey500()

    def create_asymkey500(self):
        """
        Create 500 Asymmetric keys
        """
        self.kmip_create_asymkey500()

    def verify500(self):
        """
        Fetch KMIP keys and verify it against the value in file
        """
        self.kmip_fetch500()

    def revoke500(self):
        """
        Revoke all keys
        """
        self.kmip_revoke500()

    def destroy500(self):
        """
        Destroy all keys
        """
        self.kmip_destroy500()

    def kcinfo(self):
        """
        Fetch KC information
        """
        print ("KeyControl IP: %s" % (config['hostname']))
        print ("KeyControl KMIP port: %s" % (config['port']))

if __name__ == '__main__':
    KMIPKEK()
