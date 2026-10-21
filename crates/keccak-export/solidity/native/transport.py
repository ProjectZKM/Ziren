"""Lossless field zero runs and hash dictionaries; never truncate a digest."""
import argparse
import json
from pathlib import Path


def encode(raw, fields, hashes):
    prefix = 38 + 4 * fields
    if len(raw) != prefix + 32 * hashes or raw[:6] != b'ZKET\x01\x00' or hashes > 32768:
        raise ValueError('invalid raw packet/profile dimensions')
    commands, literals, lookup = bytearray(), bytearray(), {}
    def flush():
        if literals:
            commands.extend((0x8000+len(literals)//32).to_bytes(2, 'big'))
            commands.extend(literals)
            literals.clear()
    for at in range(prefix, len(raw), 32):
        value = raw[at:at+32]
        if value not in lookup:
            lookup[value] = (at-prefix)//32
            literals.extend(value)
            if len(literals)//32 == 32767: flush()
        else:
            flush()
            commands.extend(lookup[value].to_bytes(2, 'big'))
    flush()
    return raw[:5] + b'\x02' + raw[6:prefix] + commands


def decode(encoded, fields, hashes):
    prefix = 38 + 4 * fields
    if hashes > 32768 or len(encoded) < 38 or encoded[:6] not in (b'ZKET\x01\x02',b'ZKET\x01\x03'):
        raise ValueError('invalid hash-dictionary packet')
    if encoded[5]==3:
        raw=bytearray(encoded[:5]+b'\x00'+encoded[6:38]);at=38;done=0
        while done<fields:
            if at+2>len(encoded):raise ValueError('truncated field command')
            command=int.from_bytes(encoded[at:at+2],'big');at+=2;n=command&0x7fff
            if not n or n>fields-done:raise ValueError('invalid field run')
            if command&0x8000:
                if 4*n>len(encoded)-at:raise ValueError('truncated field literals')
                raw.extend(encoded[at:at+4*n]);at+=4*n
            else:raw.extend(bytes(4*n))
            done+=n
    else:
        if len(encoded)<prefix:raise ValueError('truncated field prefix')
        raw=bytearray(encoded[:5]+b'\x00'+encoded[6:prefix]);at=prefix
    count=0
    while count < hashes:
        if at+2 > len(encoded): raise ValueError('truncated command')
        command = int.from_bytes(encoded[at:at+2], 'big'); at += 2
        if command & 0x8000:
            n = command & 0x7fff
            if not n or n > hashes-count or at+32*n > len(encoded):
                raise ValueError('invalid literal run')
            raw.extend(encoded[at:at+32*n]); at += 32*n; count += n
        else:
            if command >= count: raise ValueError('forward hash reference')
            start = prefix+32*command
            raw.extend(raw[start:start+32]); count += 1
    if at != len(encoded): raise ValueError('trailing hash commands')
    return bytes(raw)


def encode_zero_runs(raw,fields,hashes,minimum=8):
    """Lossless mode 3: BE16 field runs, then the original hash commands.

    A clear high bit expands count zero LE32 fields; a set high bit copies
    count literal LE32 fields. The threshold affects encoding cost only.
    """
    packed=encode(raw,fields,hashes)
    if type(minimum) is not int or minimum<1:raise ValueError('invalid zero-run threshold')
    result=bytearray(raw[:5]+b'\x03'+raw[6:38]);literal=bytearray();at=0
    def flush():
        if literal:
            result.extend((0x8000+len(literal)//4).to_bytes(2,'big'))
            result.extend(literal);literal.clear()
    while at<fields:
        end=at
        while end<fields and raw[38+4*end:42+4*end]==bytes(4):end+=1
        count=end-at
        if count>=minimum:
            flush()
            while count:
                n=min(count,32767);result.extend(n.to_bytes(2,'big'));count-=n;at+=n
        else:
            literal.extend(raw[38+4*at:42+4*at]);at+=1
            if len(literal)==4*32767:flush()
    flush();result.extend(packed[38+4*fields:])
    return bytes(result)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fixtures', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--zero-runs',action='store_true',help='also compress field zero runs with lossless mode 3')
    a = ap.parse_args()
    if a.out.resolve().is_relative_to(Path(__file__).resolve().parents[4]):
        ap.error('generated packets must be outside the source repository')
    meta = json.loads((a.fixtures/'compiled/program.json').read_text())['metadata']
    raw = (a.fixtures/'raw.bin').read_bytes()
    packed = (encode_zero_runs if a.zero_runs else encode)(raw, meta['field_count'], meta['hash_count'])
    assert decode(packed, meta['field_count'], meta['hash_count']) == raw
    a.out.write_bytes(packed)
    prefix = 38+4*meta['field_count']
    print(json.dumps({'raw_bytes': len(raw), 'packed_bytes': len(packed),
                      'hash_slots': meta['hash_count'],
                      'unique_hashes': len({raw[i:i+32] for i in range(prefix,len(raw),32)})}))
