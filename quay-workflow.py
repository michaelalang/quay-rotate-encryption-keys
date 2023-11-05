#!/usr/bin/python
from cryptography.fernet import Fernet, MultiFernet
import cryptography.fernet
from data.encryption import FieldEncrypter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import base64
import sys
import os
from time import sleep


def to_fkey(key):
    IKEYH = hashlib.md5(key)
    return base64.urlsafe_b64encode(IKEYH.hexdigest().encode())


def getStore():
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
                KEY2 = to_fkey(KEY2)
        CurrentStore = MultiFernet(
            map(lambda y: Fernet(y), filter(lambda x: x != b"", [KEY2, KEY1]))
        )
    except:
        print("missing DATABASE_SECRET in config")
        sys.exit(1)
    return CurrentStore


invalid = False
CurrentStore = None

while True:
    if CurrentStore == None:
        CurrentStore = getStore()
    if invalid == True:
        del CurrentStore
        print("renewing store")
        CurrentStore = getStore()
        invalid = False
    with open(".masterkey") as mk:
        MASTERKEY = mk.read().strip().encode()
    try:
        DATABASE_MASTERKEY = CurrentStore.decrypt(MASTERKEY)
    except cryptography.fernet.InvalidToken:
        print("invalid Token")
        invalid = True
        sleep(1)
        continue
    encrypter = FieldEncrypter(None)
    encrypter._secret_key = DATABASE_MASTERKEY
    with open(".data") as data:
        dvalue = encrypter.decrypt_value(data.read())
    print(f"Value: {dvalue}")
    sleep(1)
