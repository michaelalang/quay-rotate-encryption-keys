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


def rotate_masterkey():
    KEYS = []
    try:
        with open(".config.yaml") as config:
            for KEY in config.read().strip().split("\n"):
                try:
                    Fernet(KEY.strip().encode())
                    KEYS.append(KEY.strip().encode())
                except:
                    try:
                        Fernet(to_fkey(KEY.strip().encode()))
                        KEYS.append(to_fkey(KEY.strip().encode()))
                    except Exception as kerr:
                        print(f"Fernet Exception {kerr}")
                        continue
        CurrentStore = MultiFernet(map(lambda y: Fernet(y), KEYS))
    except Exception as kerr:
        print(f"missing DATABASE_SECRET_ROTATE in config {kerr}")
        sys.exit(1)
    with open(".masterkey") as mk:
        MASTERKEY = mk.read().strip().encode()
    DATABASE_MASTERKEY = CurrentStore.decrypt(MASTERKEY)
    encrypter = FieldEncrypter(None)
    encrypter._secret_key = DATABASE_MASTERKEY
    with open(".data") as data:
        dvalue = encrypter.decrypt_value(data.read())
    print(f"Value: {dvalue}")

    RotateStore = MultiFernet(map(lambda y: Fernet(y), KEYS))
    MASTERKEY = RotateStore.rotate(MASTERKEY)
    with open(".masterkey", "wb") as mk:
        mk.write(MASTERKEY)
    encrypter = FieldEncrypter(None)
    encrypter._secret_key = DATABASE_MASTERKEY
    with open(".data", "w") as data:
        data.write(encrypter.encrypt_value(dvalue))


rotate_masterkey()
