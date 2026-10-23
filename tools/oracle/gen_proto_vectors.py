#!/usr/bin/env python3
"""Generate protocol test vectors from python-validity (the reference oracle) on synthetic inputs.

Usage: gen_proto_vectors.py <path-to-python-validity> > crates/validity-proto/tests/vectors/proto.json
No device data is used: every key, identity, image and reply below is made up. The
USB/TLS layer is replaced by mocks that record the commands python-validity sends.
Large byte strings are stored as SHA-256 + length. Reruns give identical output except
for the pairing certificate's ECDSA signature (python-validity signs with a random nonce).
"""
import hashlib
import json
import sys
from hashlib import sha256
from struct import pack

sys.path.insert(0, sys.argv[1])

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import validitysensor.db as D  # noqa: E402
import validitysensor.flash as F  # noqa: E402
import validitysensor.init_flash as I  # noqa: E402
import validitysensor.sensor as S  # noqa: E402
import validitysensor.tls as T  # noqa: E402
from validitysensor import timeslot as prg  # noqa: E402
from validitysensor.hw_tables import dev_info_lookup  # noqa: E402
from validitysensor.sid import sid_from_string, sid_from_bytes  # noqa: E402
from validitysensor.table_types import SensorTypeInfo, SensorCaptureProg  # noqa: E402

WEN = b'\x06\x04\x04'  # stand-in for the vendor write-enable blob


def h(b):
    return b.hex()


def big(b):
    return {'len': len(b), 'sha256': hashlib.sha256(b).hexdigest(), 'head': b[:32].hex()}


def det(tag, n):
    out = b''
    i = 0
    while len(out) < n:
        out += sha256(b'%s-%d' % (tag.encode(), i)).digest()
        i += 1
    return out[:n]


v = {}

# --- timeslot instructions -------------------------------------------------------
dec = []
for op in range(256):
    b = bytes([op, 0x5a, 0x00])
    try:
        r = prg.decode_insn(b)
        dec.append({'op': op, 'opcode': r[0], 'len': r[1], 'args': list(r[2:])})
    except Exception:
        dec.append({'op': op, 'error': True})
v['decode_insn'] = dec

tables = []
for i, (inc, mult) in enumerate([(True, 2), (False, 2), (True, 3), (True, 1)]):
    raw = bytearray(det('ts%d' % i, 40))
    # A recognisable head: calls, noops and idles, then something else.
    head = bytes([0x10, 0x05, 0x03, 0x00, 0x07, 0x22, 0x13, 0x10, 0x01, 0x11, 0x20, 0x40, 0x00, 0x16, 0x7f, 0x04, 0x42])
    raw[:len(head)] = head
    raw = bytes(raw)
    tables.append({'in': h(raw), 'inc': inc, 'mult': mult,
                   'out': h(S.Sensor.patch_timeslot_table(None, raw, inc, mult))})
v['patch_timeslot_table'] = tables

# A table with a call to a routine holding two writes to 0x8000203c.
t = bytes([0x00, 0x06, 0x01, 0x12, 0x03, 0x02, 0x01,  # noop, enable rx, call addr 0x0c, end
           0x00, 0x00, 0x00, 0x00, 0x00,
           0x4f, 0x11, 0x22, 0x06, 0x02, 0x4f, 0x33, 0x44, 0x4e, 0x55, 0x66, 0x02])
sx = S.Sensor()
sx.factory_calibration_values = bytes(range(0x80, 0x80 + 0x40))
sx.key_calibration_line = 0x38
v['patch_timeslot_again'] = {'in': h(t), 'value': sx.factory_calibration_values[0x38],
                             'out': h(sx.patch_timeslot_again(t))}
v['find'] = {'table': h(t),
             'enable_rx_1': prg.find_nth_insn(t, 6, 1)[0], 'enable_rx_2': prg.find_nth_insn(t, 6, 2)[0],
             'write_203c_2': prg.find_nth_regwrite(t, 0x8000203c, 2)[0]}

# --- calibration arithmetic --------------------------------------------------------
v['scale'] = [S.scale(x) for x in range(256)]
v['add'] = [[l, r, S.add(l, r)] for l in range(0, 256, 7) for r in range(0, 256, 11)]
bp = []
for i, n in enumerate([1, 3, 8, 112, 144]):
    vals = det('bp%d' % i, n)
    if i == 3:
        vals = bytes(0x60 + b % 0x40 for b in vals)
    if n == 1:
        vals = b'\x00\x05'
    u, m, b = S.bitpack(vals)
    bp.append({'in': h(vals), 'u': u, 'min': m, 'out': h(b)})
v['bitpack'] = bp

# --- capture programs and a calibration session with mocked I/O --------------------


class Rom:
    def __init__(self, major, minor, build, product, u1):
        self.timestamp, self.build, self.major, self.minor, self.product, self.u1 = 0, build, major, minor, product, u1


def make_sensor(major, ver, factory_len, frames, iters, key_line, factory7):
    s = S.Sensor()
    s.device_info = dev_info_lookup(major, ver)
    s.type_info = SensorTypeInfo.get_by_type(s.device_info.type)
    s.rom_info = Rom(6, 8, 0x56, 0x30, 0)
    s.hardcoded_prog = SensorCaptureProg.get(s.rom_info, s.device_info.type, 0x18, 0x19)
    lines_2d = [int.from_bytes(v_, 'little') for k, v_ in prg.split_chunks(s.hardcoded_prog) if k == 0x2f][0]
    s.lines_per_frame = lines_2d * s.type_info.repeat_multiplier
    s.bytes_per_line = s.type_info.bytes_per_line
    s.key_calibration_line, s.calibration_frames, s.calibration_iterations = key_line, frames, iters
    s.factory_calibration_values = bytes(0x60 + b % 0x40 for b in det('factory%x' % s.device_info.type, factory_len))
    if factory7:
        s.factory_calib_data = det('factory7-%x' % s.device_info.type, 70)
    s.calib_data = b''
    return s


class Mock:
    """Records python-validity's commands and answers like a blank sensor."""

    def __init__(self, sensor_type, frame_len):
        self.sent = []
        self.frames = 0
        self.sensor_type = sensor_type
        self.frame_len = frame_len
        self.flash6 = bytearray(b'\xff' * 0x8000)

    def cmd(self, c):
        c = c() if callable(c) else c
        self.sent.append(bytes(c))
        if c[0] == 0x40:  # read flash
            part, addr, size = c[1], int.from_bytes(c[5:9], 'little'), int.from_bytes(c[9:13], 'little')
            data = bytes(self.flash6[addr:addr + size]) if part == 6 else b'\xff' * size
            return b'\0\0' + pack('<L', len(data)) + b'\0\0' + data
        if c[0] == 0x41:  # write flash
            part, addr, size = c[1], int.from_bytes(c[5:9], 'little'), int.from_bytes(c[9:13], 'little')
            if part == 6:
                self.flash6[addr:addr + size] = c[13:13 + size]
            return b'\0\0' + pack('<L', size)
        return b'\0\0'

    def read_82(self):
        self.frames += 1
        return det('frame%x-%d' % (self.sensor_type, self.frames), self.frame_len)


calib = []
for major, ver, flen, frames, iters, key_line, f7 in [(0x190, 0x59, 112, 3, 3, 0x38, False),
                                                     (0x71, 0x01, 144, 6, 0, 0x48, True)]:
    s = make_sensor(major, ver, flen, frames, iters, key_line, f7)
    frame_len = (s.calibration_frames * s.lines_per_frame + 1) * s.bytes_per_line
    m = Mock(s.device_info.type, frame_len)
    S.tls.cmd = m.cmd
    S.tls.app = m.cmd
    F.tls.cmd = m.cmd
    S.usb.read_82 = m.read_82
    F.db_write_enable = WEN
    S.calib_data_path = '/nonexistent/validity-rs-oracle/calib-data.bin'
    S.Sensor.save = lambda self: None
    s.calibrate()
    entry = {
        'major': major, 'version': ver, 'sensor_type': s.device_info.type,
        'factory_values': h(s.factory_calibration_values),
        'factory_calib_data': h(s.factory_calib_data) if f7 else None,
        'key_line': key_line, 'frames': frames, 'iterations': iters,
        'lines_per_frame': s.lines_per_frame, 'frame_len': frame_len,
        'sent': [big(c) for c in m.sent],
        'calib_data': big(s.calib_data),
        'identify': big(s.build_cmd_02(S.CaptureMode.IDENTIFY)),
        'enroll': big(s.build_cmd_02(S.CaptureMode.ENROLL)),
        'calibrate': big(s.build_cmd_02(S.CaptureMode.CALIBRATE)),
    }
    # The same programs before any calibration (empty calibration data).
    s.calib_data = b''
    entry['identify_uncalibrated'] = big(s.build_cmd_02(S.CaptureMode.IDENTIFY))
    calib.append(entry)
v['calibration_sessions'] = calib

# --- pairing -----------------------------------------------------------------------
t = T.Tls(T.usb)
t.set_hwkey('ThinkPad Synthetic', 'SYNTH0001')
I.tls = t
d = int.from_bytes(det('host-d', 32), 'big') % (2 ** 255)
key = ec.derive_private_key(d, ec.SECP256R1())
pub = key.private_numbers().public_numbers
I.os.urandom = lambda n: det('pair-iv', n)
cert = I.make_cert(pub)
priv_blob = I.encrypt_key(d, pub)
ic = F.flash_ic_table_lookup(0xef, 0x40, 0x100000)
sent = []
host_cert = det('host-cert', 184)
I.tls.cmd = lambda c: (sent.append(c), b'\0\0' + pack('<L', len(host_cert)) + host_cert + b'\xee' * 8)[1]
I.tls.handle_cert = lambda b: setattr(t, 'tls_cert', b)
I.make_cert = lambda _pub: cert  # its ECDSA nonce is random: reuse the certificate above
I.partition_flash(F.FlashInfo(ic, 0x100, 0, 0x1000, 0, []), I.flash_layout_hardcoded,
                  det('partition-signature', 256), pub)
t.priv_blob = priv_blob
t.ecdh_blob = det('ecdh-blob', 400)
v['pairing'] = {
    'product': 'ThinkPad Synthetic', 'serial': 'SYNTH0001',
    'd': '%064x' % d, 'iv': h(det('pair-iv', 16)),
    'cert': h(cert), 'priv_blob': h(priv_blob),
    'partition_signature': h(det('partition-signature', 256)),
    'partition_cmd': h(sent[0]),
    'host_cert': h(host_cert), 'ecdh_blob': h(t.ecdh_blob),
    'tls_flash': h(t.make_tls_flash()),
    'crt_hardcoded': h(T.crt_hardcoded),
    'flash_params': h(I.serialize_flash_params(ic)),
}

# --- database ----------------------------------------------------------------------
sid = sid_from_string('S-1-5-21-1000000001-2000000002-3000000003-1234')
ident = D.identity_to_bytes(sid)
stg_reply = b'\0\0' + pack('<HHHH', 3, 2, 11, 0) + pack('<HHHH', 0x11, 0x4c, 0x12, 0x4c) + b'StgWindsor\0'
user_reply = (b'\0\0' + pack('<HHHH', 0x11, 2, 0, len(ident)) + pack('<HHHH', 0x21, 1, 3, 0x0123)
              + pack('<HHHH', 0x22, 6, 3, 0x0456) + ident)
st = D.parse_user_storage(stg_reply)
u = D.parse_user(user_reply)
v['db'] = {
    'sid': repr(sid), 'sid_bytes': h(sid.to_bytes()), 'identity': h(ident),
    'sid_round_trip': repr(sid_from_bytes(sid.to_bytes())),
    'storage_reply': h(stg_reply), 'storage': {'dbid': st.dbid, 'name': h(st.name), 'users': st.users},
    'user_reply': h(user_reply),
    'user': {'dbid': u.dbid, 'identity': repr(u.identity), 'fingers': u.fingers},
    'finger_data': h(S.Sensor.make_finger_data(None, 7, det('template', 300), det('tid', 32))),
}
sent = []
D.tls.cmd = lambda c: (sent.append(c() if callable(c) else c),
                       {0x45: b'\0\0' + bytes(24), 0x47: b'\0\0\x31\x00', 0x4b: stg_reply}.get(
                           (c() if callable(c) else c)[0], b'\0\0'))[1]
F.tls.cmd = D.tls.cmd
D.db_write_enable = WEN
F.db_write_enable = WEN
D.db.new_user(sid)
D.db.new_finger(0x11, b'tinfo')
D.db.new_data(0x22, b'data')
D.db.new_user_storate()
v['db']['commands'] = [h(c) for c in sent]

# --- sensor replies ----------------------------------------------------------------
fb = (b'\0\0' + pack('<LL', 7, 3) + pack('<LHHHH', 8, 6, 0x0e00, 3, 0x8000) + b'\x07\0\0\0\x80\x81'
      + pack('<LHHHH', 0x20, 2, 0x0e00, 2, 0) + b'\x0d\x00' + pack('<LHHHH', 0x30, 0, 0x0e00, 7, 0x8000))
S.tls.cmd = lambda c: fb
v['factory_bits'] = {'reply': h(fb), 'bits': {str(k): h(x) for k, x in S.get_factory_bits(0x0e00).items()}}

upd = (pack('<HH', 1, 4) + bytes(0x34) + b'HDR!' + pack('<HH', 0, 6) + det('tpl', 0x34) + b'TEMPL!'
       + pack('<HH', 2, 1) + bytes(0x34) + b'X' + pack('<HH', 3, 3) + bytes(0x34) + b'TID')
upd = pack('<H', len(upd)) + upd
S.tls.app = lambda c: b'\0\0' + upd
S.tls.cmd = lambda c: b'\0\0'
S.usb.wait_int = lambda: b'\x05\x02\x02\x02\x02'
F.tls.cmd = S.tls.cmd
S.call_cleanups = lambda: None
header, template, tid = S.Sensor().append_new_image(b'prev')
v['enrollment_update'] = {'reply': h(upd), 'header': h(header), 'template': h(template), 'tid': h(tid)}

res = pack('<HH', 1, 4) + pack('<L', 0x11) + pack('<HH', 3, 2) + pack('<H', 6) + pack('<HH', 4, 5) + b'HASH5'
res = b'\0\0' + pack('<H', len(res)) + res
replies = {0x5e: b'\0\0', 0x60: res, 0x62: b'\0\0'}
S.tls.app = lambda c: replies[c[0]]
S.usb.wait_int = lambda: b'\x03\x02\x02\x02\x02'
usr, sub, hsh = S.Sensor().match_finger()
v['match'] = {'reply': h(res), 'user': usr, 'subtype': sub, 'hash': h(hsh)}

fi = (b'\0\0' + pack('<HHHHHHH', 0xef, 0x40, 0x100, 0, 0x1000, 0, 2) + pack('<BBHLL', 1, 4, 7, 0x1000, 0x1000)
      + pack('<BBHLL', 4, 3, 5, 0x50000, 0x80000))
F.tls.cmd = lambda c: fi
info = F.get_flash_info()
v['flash_info'] = {'reply': h(fi), 'ic': info.ic.name, 'blocks': info.blocks, 'blocksize': info.blocksize,
                   'partitions': [[p.id, p.type, p.access_lvl, p.offset, p.size] for p in info.partitions]}
fw = b'\0\0' + pack('<HHHL', 3, 4, 2, 0x60000000) + pack('<HHHHL', 1, 0x1111, 1, 2, 0x2000) + pack('<HHHHL', 2, 0x2222, 3, 4, 0x3000)
F.tls.cmd = lambda c: fw
fwi = F.get_fw_info(2)
v['fw_info'] = {'reply': h(fw), 'major': fwi.major, 'minor': fwi.minor, 'buildtime': fwi.buildtime,
                'modules': [[m.type, m.subtype, m.major, m.minor, m.size] for m in fwi.modules]}

print(json.dumps(v, indent=1, sort_keys=True))
