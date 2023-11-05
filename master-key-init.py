#!/usr/bin/python
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from data.encryption import FieldEncrypter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import base64
import sys
import uuid
import os
from time import time
from util.security.secret import convert_secret_key


def to_fkey(key):
    IKEYH = hashlib.md5(key)
    return base64.urlsafe_b64encode(IKEYH.hexdigest().encode())


try:
    with open(".config.yaml") as config:
        try:
            KEY1 = config.readline().strip().encode()
            Fernet(KEY1)
        except:
            KEY1 = to_fkey(KEY1)
    CurrentStore = MultiFernet([Fernet(KEY1)])
except:
    KEY = to_fkey(sys.argv[1].encode())
    CurrentStore = MultiFernet([Fernet(KEY1)])

try:
    RKEY = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(time())))
    MASTERKEY = convert_secret_key(RKEY)
    MASTERKEY = CurrentStore.encrypt(MASTERKEY)
    with open(".masterkey", "wb") as data:
        data.write(MASTERKEY)
except Exception as kerr:
    print(kerr)
    sys.exit(1)

DATABASE_MASTERKEY = CurrentStore.decrypt(MASTERKEY)
encrypter = FieldEncrypter(None)
encrypter._secret_key = DATABASE_MASTERKEY
with open(".data", "w") as data:
    data.write(encrypter.encrypt_value(sys.argv[1]))
