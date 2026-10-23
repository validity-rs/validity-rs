#!/usr/bin/env python3
"""Locate python-validity's 06cb:009a blobs inside the vendor driver DLL.

Usage: blob_offsets.py <path-to-python-validity> <synaWudfBioUsb.dll>
Each blob is a 0x06 command byte followed by a contiguous run of the DLL. Prints the
offset, length and SHA-256 of each, so validity-rs can extract them at install time
instead of shipping them. The partition table signature (init_flash.py) is a raw run,
without command byte, located the same way.
"""
import hashlib
import re
import sys
import types

pkg = types.ModuleType('validitysensor')
pkg.__path__ = [sys.argv[1] + '/validitysensor']
sys.modules['validitysensor'] = pkg
import validitysensor.blobs_9a as b  # noqa: E402

dll = open(sys.argv[2], 'rb').read()
print('dll_sha256', hashlib.sha256(dll).hexdigest(), len(dll))
for name in ('init_hardcoded', 'init_hardcoded_clean_slate', 'reset_blob', 'db_write_enable'):
    blob = getattr(b, name)
    assert blob[0] == 6, name
    off = dll.find(blob[1:])
    assert off >= 0 and dll.find(blob[1:], off + 1) < 0, name  # present exactly once
    print(name, hex(off), len(blob) - 1, hashlib.sha256(blob).hexdigest())

# init_flash.py imports the USB stack; read the constant from its source instead.
src = open(sys.argv[1] + '/validitysensor/init_flash.py').read()
m = re.search(r"^partition_signature = unhex\('''([0-9a-f\s]+)'''\)", src, re.M)
sig = bytes.fromhex(''.join(m.group(1).split()))
off = dll.find(sig)
assert off >= 0 and dll.find(sig, off + 1) < 0, 'partition_signature'
print('partition_signature', hex(off), len(sig), hashlib.sha256(sig).hexdigest())
