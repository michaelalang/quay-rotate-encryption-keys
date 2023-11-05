# Quay Database encryption key rotate workflow

## Target of the exercise

We want to understand and showcase the possibility of having a `DATABASE_SECRET_KEY` that follows these criterias:
* the key to encrypt is unknown to `anyone`
* the `DATABASE_SECRET_KEY` decrypts the key for field encryption
* the `DATABASE_SECRET_KEY` can be rotated safely
    * without the need to re-encrypt all fields

## Proof of concept

to simplify the POC, we do not utilize a Database but store any item within the file system. Those are
* `.master_key` which is used to decrypt the fields 
* `.data` representing any Database field with an encyrpted value
* `.config.yaml` representing the Quay config bunlde but simplified to `DATABASE_SECRET_KEY` value

# Workflow

## preparing the structure and POC

* checkout the current quay code

```
git clone https://github.com/quay/quay.git
```

this is mandatory as we do want to use the existing classes and methods to understand the implications to the code.

* change inside the quay clone directory 

* fetch the three scripts emulating the lifecycles of Quay data
    * [master-key-init.py](https://raw.githubusercontent.com/michaelalang/quay-rotate-encryption-keys/main/master-key-init.py)
    * [quay-workflow.py](https://raw.githubusercontent.com/michaelalang/quay-rotate-encryption-keys/main/quay-workflow.py)
    * [master-key-workflow.py](https://raw.githubusercontent.com/michaelalang/quay-rotate-encryption-keys/main/master-key-workflow.py)


* configure your initial `DATABASE_SECRET_KEY` value
```
echo changeme > .config.yaml
```

* initialize an empty Quay deployment

```
# Synatx:
# ./master-key-init.py <sensitive-data-example>

$ ./master-key-init.py very-senstive-data-$(uuidgen)
```

* verify that `.data` contains a value similar to 
```
$ cat .data
v0$$OwvBHvqFMdITsj0n1f0c5XC/2lZ63Ly0q6fSJFwqZx4DzjmixDwiPTOQ3qt0Ab4=
```

* verify that `.masterkey` contains no plain-text value either
```
$ cat .masterkey
gAAAAABlR13xiDAjaryNx7gJVbMOhzqX4lPiosKujtmr09ZbvWkfrY_uBucmWmYQ51gER7mhArQ16OHPomaxsU5rVyXhvCYeT9sk8ioSnVWhGzvhm8pKeThWlfDCvTn6JVp5Mk66vVmM
```

* open a new terminal to start the continuous loop quay-workflow script.

* verify the Quay workflow emulating reading/writing data (NOTE: we do not write with the same master-key to simplify the POC)
```
$ ./quay-workflow.py 
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
...
```

* POC `DATABASE_SECRET_KEY` rotation (NOTE: changing does not reencrypt data but reencrypts the encrypted `master-key`)

* add the `DATABASE_SECRET_ROTATE` 
```
$ echo new-change-me >> .config.yaml
```

```
$ ./master-key-workflow.py
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
```

* verify that the old `DATABASE_SECRET_KEY` isn't working anymore looking at the `quay-workflow` terminal
  understand that the script mimics the restart of quay so only one error will be shown
```
...
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
invalid Token
renewing store
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
...
...
```

* rotate the `DATABASE_SECRET_ROTATE` to the `DATABASE_SECRET` 
```
# rotate the DATABASE_SECRET_ROTATE to DATABASE_SECRET
$ echo new-change-me > .config.yaml
```

* verify that the `NewKey|DATABASE_SECRET_KEY` is working as expected

```
...
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
```

* verify that restarting the `quay-workflow` is working as expected 
```
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
..
[CTRL+C]
^CTraceback (most recent call last):
  File "./quay-workflow.py", line 66, in <module>
    sleep(1)
KeyboardInterrupt

$ ./quay-workflow.py
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
Value: very-senstive-data-5818ec73-4cd0-4258-a52a-c50ad77d068b
...
```

## Quay configuration changes 

As showcased in the POC the rotation of `DATABASE_SECRET_KEY` values requires a restart of the Quay application. Furthermore, two restarts are necesary to:
* introduce a new `DATABASE_SECRET_KEY` to the Quay instances
* remove the revoded `DATABASE_SECRET_KEY` from the Quay instances

This can be done by utilizing a new config parameter like `DATABASE_SECRET_ROTATE: <new-key>`
After key rotation has finished the parameter needs to be removed again and `DATABASE_SECRET_KEY` needs to be updated with the `<new-key>` value instead.

Reason the revoke and restart is necessary:

* if handled without a restart, the decryption of the master-key will still be working due to how Fernet handles multiple keys in decryption

### Quay code changes necessary 

* Quay's `FieldEncrypter` expects an `util.security.secret/convert_secret_key` which takes a config argument as content and not a decrypted bytes object.
```
# current code
# instead of 
DATABASE_MASTERKEY = CurrentStore.decrypt(MASTERKEY)
encrypter = FieldEncrypter(DATABASE_MASTERKEY)

# we need to initialize the FieldEncrypter as follows
DATABASE_MASTERKEY = CurrentStore.decrypt(MASTERKEY)
encrypter = FieldEncrypter(None)
encrypter._secret_key = DATABASE_MASTERKEY
```

### Fernet TTL feature

by default, Fernet does not enforce a TTL on the tokens it generates. That is on one side good to ensure, tokens are not getting rendered invalid without an explict workflow and brings the opportunity to imply policies on notifications/force re-encryption of the master key.

### Future enhancments 

with still need at least two restart of the Quay instances to ensure transparent re-encryption of the master key. That is necessary since we do not re-read or reload configurations at runtime.
As seen in the `quay-workflow.py` the automatic reload of the Fernet could be done.
