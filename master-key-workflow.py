#!/usr/bin/python
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from data.encryption import FieldEncrypter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import base64
import sys
import os


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
        try:
            KEY2 = config.readline().strip().encode()
            Fernet(KEY2)
        except:
            if KEY2 == b"":
                raise Exception("DATABASE_SECRET_ROTATE not in config")
            KEY2 = to_fkey(KEY2)
    CurrentStore = MultiFernet(
        map(lambda y: Fernet(y), filter(lambda x: x != None, [KEY2, KEY1]))
    )
except Exception as kerr:
    print("missing DATABASE_SECRET_ROTATE in config")
    sys.exit(1)

with open(".masterkey") as mk:
    MASTERKEY = mk.read().strip().encode()
DATABASE_MASTERKEY = CurrentStore.decrypt(MASTERKEY)
encrypter = FieldEncrypter(None)
encrypter._secret_key = DATABASE_MASTERKEY
with open(".data") as data:
    dvalue = encrypter.decrypt_value(data.read())
print(f"Value: {dvalue}")

RotateStore = MultiFernet([Fernet(KEY2), Fernet(KEY1)])
MASTERKEY = RotateStore.rotate(MASTERKEY)
with open(".masterkey", "wb") as mk:
    mk.write(MASTERKEY)
encrypter = FieldEncrypter(None)
encrypter._secret_key = DATABASE_MASTERKEY
with open(".data", "w") as data:
    data.write(encrypter.encrypt_value(dvalue))
