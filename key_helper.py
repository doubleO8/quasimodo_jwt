#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from Cryptodome.PublicKey import RSA

def key_pair(prefix):
    key = RSA.generate(2048)
    priv_key = '{prefix}_private.pem'.format(prefix=prefix)
    pub_key = '{prefix}_pub.pem'.format(prefix=prefix)

    if os.path.isfile(priv_key):
        return priv_key, pub_key
    private_key = key.export_key()
    file_out = open(priv_key, "wb")
    file_out.write(private_key)

    public_key = key.publickey().export_key()
    file_out = open(pub_key, "wb")
    file_out.write(public_key)

    return priv_key, pub_key

if __name__ == '__main__':
    key_pair("test")
