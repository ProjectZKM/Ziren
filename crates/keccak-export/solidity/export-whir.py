#!/usr/bin/env python3
"""Encode native WHIR component vectors for the test-only transport harness."""
import json
import sys
from pathlib import Path

def main():
 a=json.loads(Path(sys.argv[1]).read_text());p=a['proof'];c=a['config'];e=a['entry'];out=bytearray(b'ZKWP')
 def n(v,k=1):out.extend((int(v,0) if isinstance(v,str) else int(v)).to_bytes(k,'big'))
 def raw(v):out.extend(bytes.fromhex(v.removeprefix('0x')))
 def vec(v,width,count=1):
  n(len(v),count)
  for x in v:n(x,width)
 def hashes(v):
  n(len(v))
  for x in v:raw(x)
 def polys(v):
  n(len(v))
  for x in v:vec(x,16)
 for key in ['n','startingRate','batchPow']:n(c[key])
 n(c['finalQueries'],2);n(c['finalPow']);n(len(c['rounds']))
 for r in c['rounds']:
  n(r['fold']);n(r['rate']);n(r['queries'],2);n(r['ood']);n(r['queryPow']);vec(r['foldPow'],1)
 raw(e['digest']);buffer=bytes.fromhex(e['buffered'][2:]);n(len(buffer));out.extend(buffer);n(e['wordsLeft'])
 hashes(a['roots']);vec(a['stripes'],2);vec(a['point'],16)
 n(len(p['batch']))
 for r in p['batch']:vec(r,16,2)
 n(p['batchPow'],4);n(len(p['roundPolys']))
 for r in p['roundPolys']:polys(r)
 n(len(p['roundOod']))
 for r in p['roundOod']:vec(r,16)
 hashes(p['roots']);n(len(p['openings']))
 for group in p['openings']:
  n(len(group),2)
  for leaf in group:
   n(len(leaf['values']),2)
   for row in leaf['values']:vec(row,4,2)
   hashes(leaf['path'])
 vec(p['finalPoly'],16,2);polys(p['finalPolys']);vec(p['foldPow'],4);n(p['finalPow'],4)
 Path(sys.argv[2]).write_bytes(out);print('component bytes',len(out))
if __name__=='__main__':main()
