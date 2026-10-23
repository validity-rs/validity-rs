#!/usr/bin/env python3
"""Generate TLS test vectors from python-validity (the reference oracle) on synthetic inputs.

Usage: gen_tls_vectors.py <path-to-python-validity> > crates/validity-proto/tests/vectors/tls.json
No device data is used: every key, random and hardware id below is made up.
"""
import hmac
import json
import sys
from hashlib import sha256

sys.path.insert(0, sys.argv[1])

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

import validitysensor.tls as T  # noqa: E402


def h(b):
    return b.hex()


def det(tag, n):
    """Deterministic pseudo-random bytes."""
    out = b''
    i = 0
    while len(out) < n:
        out += sha256(b'%s-%d' % (tag.encode(), i)).digest()
        i += 1
    return out[:n]


def le32(n):
    return n.to_bytes(32, 'little')


v = {}

v['prf'] = [{'secret': h(det('s%d' % i, 7 + i * 9)), 'seed': h(det('d%d' % i, 13 + i * 5)), 'len': n,
             'out': h(T.prf(det('s%d' % i, 7 + i * 9), det('d%d' % i, 13 + i * 5), n))}
            for i, n in enumerate([0xc, 0x20, 0x30, 0x120])]

v['hs_key'] = '%064x' % T.hs_key()

v['pad'] = [{'in': h(det('p%d' % n, n)), 'out': h(T.pad(det('p%d' % n, n)))} for n in (0, 1, 15, 16, 17, 31)]

t = T.Tls(T.usb)
t.set_hwkey('ThinkPad Synthetic', 'SYNTH0001')
v['psk'] = {'product': 'ThinkPad Synthetic', 'serial': 'SYNTH0001',
            'encryption_key': h(t.psk_encryption_key), 'validation_key': h(t.psk_validation_key)}

# Private key blob (flash block 4), built like a paired device would, then parsed by the oracle.
d = int.from_bytes(det('client-d', 32), 'big') % (2**255)
pk = ec.derive_private_key(d, ec.SECP256R1()).private_numbers().public_numbers
plain = le32(pk.x) + le32(pk.y) + le32(d)
plain += bytes([16 - len(plain) % 16]) * (16 - len(plain) % 16)  # standard PKCS#7 here
iv = det('priv-iv', 16)
enc = Cipher(algorithms.AES(t.psk_encryption_key), modes.CBC(iv)).encryptor()
c = iv + enc.update(plain) + enc.finalize()
priv_blob = b'\x02' + c + hmac.new(t.psk_validation_key, c, sha256).digest()
t.handle_priv(priv_blob)
assert t.priv_key.private_numbers().private_value == d
v['priv_blob'] = {'blob': h(priv_blob), 'd': '%064x' % d}

v['flash_block'] = {'id': 4, 'body': h(priv_blob), 'out': h(t.make_tls_flash_block(4, priv_blob))}

# Session keys: fixed ephemeral key, fixed server ECDH key, fixed randoms.
eph = ec.derive_private_key(int.from_bytes(det('eph', 32), 'big') % (2**255), ec.SECP256R1())
srv = ec.derive_private_key(int.from_bytes(det('srv', 32), 'big') % (2**255), ec.SECP256R1())
t.ecdh_q = srv.public_key()
t.client_random, t.server_random = det('cr', 32), det('sr', 32)
T.ec.generate_private_key = lambda *a, **k: eph
t.make_keys()
sp = srv.public_key().public_numbers()
v['keys'] = {'eph_d': '%064x' % eph.private_numbers().private_value,
             'server_x': '%064x' % sp.x, 'server_y': '%064x' % sp.y,
             'client_random': h(t.client_random), 'server_random': h(t.server_random),
             'master_secret': h(t.master_secret), 'sign_key': h(t.sign_key),
             'validation_key': h(t.validation_key), 'encryption_key': h(t.encryption_key),
             'decryption_key': h(t.decryption_key)}

# Record layer: sign + encrypt with a fixed IV, then the reverse with swapped keys.
payload = det('app', 37)
T.os.urandom = lambda n: det('iv', n)
t.secure_tx = True
rec = t.make_app_data(payload)
v['app_record'] = {'payload': h(payload), 'iv': h(det('iv', 16)), 'record': h(rec)}
t.decryption_key, t.validation_key = t.encryption_key, t.sign_key
t.secure_rx = True
assert t.parse_tls_response(rec) == payload

# Client hello with a fixed random; handshake hash after it.
t.handshake_hash = sha256()
T.os.urandom = lambda n: det('hello', n)
hello = t.make_client_hello()
v['client_hello'] = {'random': h(det('hello', 32)), 'msg': h(hello),
                     'record': h(b'\x16\x03\x03' + T.with_2bytes_size(hello))}

# Finished messages over a fixed handshake hash.
t.handshake_hash = sha256(b'synthetic transcript')
v['finished'] = {'transcript': h(b'synthetic transcript'), 'client': h(t.make_finish()),
                 'server_verify': h(T.prf(t.master_secret, b'server finished' +
                                          sha256(b'synthetic transcript').digest(), 0xc))}

print(json.dumps(v, indent=1, sort_keys=True))
