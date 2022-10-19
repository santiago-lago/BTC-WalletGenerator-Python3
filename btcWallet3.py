#!/usr/bin/env python3

import os, binascii, hashlib, base58, ecdsa
import random

def shex(x):
    return binascii.hexlify(x).decode()
    
def b58wchecksum(x):
    checksum = hashlib.sha256(hashlib.sha256(x).digest()).digest()[:4]
    return base58.b58encode(x+checksum)
    
def ripemd160(x):
    d = hashlib.new("ripemd160")
    d.update(x)
    return d
    
# generate private key
random.seed(1012390129021902390)
priv_key = bytes([random.randint(0, 255) for x in range (32)])

# priv_key -> WIF
fullkey = b"\x80" + priv_key
WIF = b58wchecksum(fullkey)
print(WIF)

# get public key    
sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
vk = sk.get_verifying_key()
publ_key = b"\x04" + vk.to_string()
hash160 = ripemd160(hashlib.sha256(publ_key).digest()).digest()
publ_addr_a = b"\x00" + hash160
publ_addr_b = b58wchecksum(publ_addr_a)
print(publ_addr_b)



