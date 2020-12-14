#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
import authlib
from authlib.jose import jwk
from authlib.jose import jwt


def load_jwk(path):
    with open(path, "rb") as src:
        return jwk.dumps(src.read(), kty='RSA')


def parse_jwt_claim(token, pub_key):
    data = {
        'valid': False,
        'payload': dict()
    }

    try:
        claims = jwt.decode(token, pub_key)
    except (authlib.jose.errors.DecodeError,
            authlib.jose.errors.BadSignatureError):
        return data

    try:
        claims.validate()
    except authlib.jose.errors.BadSignatureError:
        return data

    data['payload'] = dict(claims)
    data['valid'] = True

    return data


def create_jwt_claim(priv_key, payload, alg=None):
    if alg is None:
        alg = 'RS256'

    header = {'alg': alg}

    return jwt.encode(header, payload, priv_key)
