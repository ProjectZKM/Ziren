#!/usr/bin/env python3
"""Differential EVM tests for generated Poseidon and batched inversions.

Requires deployed baseline/candidate manifests from native/measure.py on a
local chain 31337. Generated harnesses and reports stay under --out.
"""
import argparse,sys,json,random,time,importlib.util,urllib.request,urllib.parse
from pathlib import Path
sys.dont_write_bytecode=True
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--fixtures',type=Path,required=True)
ap.add_argument('--baseline',type=Path,help='approved baseline for inverse comparisons; omit with --hash-only')
ap.add_argument('--build',type=Path,required=True)
ap.add_argument('--out',type=Path,required=True)
ap.add_argument('--solc',required=True)
ap.add_argument('--rpc',default='http://127.0.0.1:18600')
ap.add_argument('--hash-only',action='store_true',help='compare all 16 Poseidon state words without rerunning unchanged inverse tests')
ap.add_argument('--redeploy-baseline',action='store_true',help='redeploy the pinned baseline inverse kernel on the local test chain')
args=ap.parse_args()
if not args.hash_only and args.baseline is None:ap.error('--baseline is required unless --hash-only is set')
repo=Path(__file__).resolve().parents[1];sys.path.insert(0,str(repo/'native'))
assert not args.out.resolve().is_relative_to(repo.parents[2]),'artifacts must stay outside the repository'
assert urllib.parse.urlparse(args.rpc).hostname in ('localhost','127.0.0.1'),'local benchmark only'
sp=importlib.util.spec_from_file_location('gen',repo/'native/compile.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
out=args.out;out.mkdir(parents=True,exist_ok=True);cache=out/'cache';cache.mkdir(exist_ok=True)
fix=args.fixtures;approved=json.loads((fix/'compiled/program.json').read_text());c=m.Compiler(approved,(fix/'compiled/program.bin').read_bytes());rng=random.Random(8391031)
word=lambda x:x.to_bytes(32,'big')
def rpc(method,params):
 req=urllib.request.Request(args.rpc,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=300) as res:r=json.load(res)
 if 'error' in r:raise RuntimeError(r['error'])
 return r['result']
assert int(rpc('eth_chainId',[]),16)==31337,'local benchmark only'
account=rpc('eth_accounts',[])[0]
def deploy(b):
 h=rpc('eth_sendTransaction',[{'from':account,'data':'0x'+b,'gas':hex(10000000)}])
 for _ in range(200):
  r=rpc('eth_getTransactionReceipt',[h])
  if r:break
  time.sleep(.05)
 assert int(r['status'],16)==1
 return r['contractAddress']
def call(addr,b):return rpc('eth_call',[{'to':addr,'data':'0x'+b.hex(),'gas':hex(100000000)},'latest'])
poseidon=next(op for op in c.ops if op[0]==18)[-1]
selected_manifest=json.loads((args.build/'native.json').read_text())
hash_kernel=next(k for k in selected_manifest['kernels'] if any(op[0]==18 for op in c.ops[k['start']:k['end']]))
diag=__import__('re').search(r'hex"([0-9a-f]+)"',(repo/'src/KoalaBearPoseidon2.sol').read_text())[1]
addresses=[]
for fast in (False,True):
 helpers=m.helpers(0,True,poseidon if fast else None,loop_partial_rounds=bool(fast and selected_manifest.get('loop_partial_rounds')),tracked_partial_sum=bool(fast and selected_manifest.get('tracked_partial_sum')))
 setup='' if fast else 'codecopy(2048,dataoffset("constants"),1792) mstore(3840,0x'+diag[:64]+') mstore(3872,0x'+diag[64:]+')'
 data='' if fast else 'data "constants" hex"'+poseidon+'"'
 code='''mstore(0x40,memoryguard(4096))
 for {let i:=0} lt(i,512) {i:=add(i,32)} {mstore(add(512,i),0)}
 SETUP
 for {let at:=0} lt(at,calldatasize()) {at:=add(at,256)} {
  let n:=sub(calldatasize(),at) if gt(n,256){n:=256}
  for{let j:=0} lt(j,n){j:=add(j,32)} {mstore(add(512,j),calldataload(add(at,j)))}
  permute(512,1024,2048,3840)
 }
 return(512,512)'''.replace('SETUP',setup)
 name='HashFast' if fast else 'HashOriginal';source='object "'+name+'" {code{datacopy(0,dataoffset("R"),datasize("R")) return(0,datasize("R"))} object "R" {code{'+helpers+'\n'+code+'} '+data+'}}'
 (out/(name+'.yul')).write_text(source)
 artifact=m.compile_yul(args.solc,source,name,cache,hash_kernel['optimizer'] if fast else 'minimal',180,runs=hash_kernel['optimizer_runs'] if fast else 1);assert len(artifact['runtime'])//2<=24576
 addresses.append(deploy(artifact['bytecode']))
lengths=[0,1,7,8,9,15,16,17,223,224,225]+[rng.randrange(257) for _ in range(64)]
for n in lengths:
 for edge in (False,True):
  values=[m.P-1 if edge else rng.randrange(m.P) for _ in range(n)];packet=b''.join(map(word,values))
  assert call(addresses[0],packet)==call(addresses[1],packet),(n,edge)
print('Poseidon: 150 independent generic/specialized sponge comparisons pass',flush=True)
if args.hash_only:
 (out/'report.json').write_text(json.dumps({'poseidon_cases':150,'state_words_per_case':16,'matches_original_generic_evm':True,'scope':'Poseidon only; unchanged inverse comparisons not rerun'},indent=2)+'\n')
 raise SystemExit(0)
old=json.loads((args.baseline/'deployments.json').read_text());new=json.loads((args.build/'deployments.json').read_text());manifest=json.loads((args.build/'native.json').read_text());baseline=json.loads((args.baseline/'native.json').read_text())
assert baseline['source_program_hash']==manifest['source_program_hash']=='0x'+c.program_hash.hex()
old_index=next(i for i,x in enumerate(baseline['kernels']) if x['start']==1024)
lo=baseline['kernels'][old_index]['start'];hi=baseline['kernels'][old_index]['end']
assert set(op[0] for op in c.ops[lo:hi])=={4,6,7}
old_meta=baseline['kernels'][old_index];old_address=old[old_index]['address']
if args.redeploy_baseline:
 old_address=deploy(old_meta['bytecode'])
 old[old_index]=dict(old[old_index],address=old_address)
k=next(i for i,x in enumerate(manifest['kernels']) if x['start']<=lo<hi<=x['end'])
if (manifest['kernels'][k]['start'],manifest['kernels'][k]['end'])==(lo,hi):
 new_address=new[k]['address'];new_meta=manifest['kernels'][k];comparison_scope='selected deployed kernel'
else:
 # Repartitioning can merge this pure inverse span with observations/asserts.
 # Random math vectors are not valid arbitrary machine proofs. Compile exactly
 # the pure span with the selected generator flags and compare it separately;
 # measure.py covers the actual selected boundaries with the saved full proof.
 selected=m.Compiler(approved,(fix/'compiled/program.bin').read_bytes())
 if manifest.get('assertion_facts'):selected.specialize_assertions()
 if manifest.get('dead_arithmetic_operations'):selected.eliminate_dead_arithmetic()
 if manifest.get('proof_cache_indices') is not None:selected.prepare_proof_cache()
 for key in ('fast_poseidon','batch_inverse','tower_mulmod','bulk_observe','fast_sample','fused_dot','matrix_cache','matrix_min_uses','matrix_left_only','branchless_products','loop_partial_rounds','identity_branch_spans','contiguous_results'):
  setattr(selected,key,manifest.get(key,False))
 name='SelectedInverseSubsequence';source=selected.kernel(lo,hi,name);(out/(name+'.yul')).write_text(source)
 built=m.compile_yul(args.solc,source,name,cache,'full',60,runs=1);assert len(built['runtime'])//2<=24576
 new_address=deploy(built['bytecode']);new_meta={'code_hash':'0x'+m.kh(bytes.fromhex(built['runtime'])).hex(),
  'write_registers':selected.register_access(lo,hi)[1],'constant_preconditions':selected.constant_preconditions(lo) if manifest.get('assertion_facts') else {'fields':{},'registers':{}}}
 comparison_scope='pure original subsequence compiled with selected generator flags; full selected boundaries checked separately'
for deployment,meta in [(old[old_index],old_meta),({'address':new_address},new_meta)]:
 assert m.kh(bytes.fromhex(rpc('eth_getCode',[deployment['address'],'latest'])[2:])).hex()==meta['code_hash'][2:],'missing or mismatched kernel'
indices=[op[2]&0x0fffffff for op in c.ops[lo:hi] if op[0]==7];assert len(indices)==171
raw=(fix/'raw.bin').read_bytes();context=bytearray(c.packet+len(raw));context[c.prefix:c.packet]=word(len(raw));context[c.packet:]=raw
facts=new_meta.get('constant_preconditions',{'fields':{},'registers':{}})
def apply_facts(packet):
 for reg,value in facts['registers'].items():packet[32*int(reg):32*int(reg)+32]=word(value)
 for field,value in facts['fields'].items():
  at=c.packet+38+4*int(field);packet[at:at+4]=value.to_bytes(4,'little')
def kernel_call(target,packet,meta,profile):
 data=bytearray(packet)
 if profile.get('proof_cache_indices') is not None:
  data.extend(bytes(profile['context_bytes']-len(data)))
  start=c.packet+len(raw)
  for i,index in enumerate(profile['proof_cache_indices']):
   value=int.from_bytes(packet[c.packet+38+4*index:c.packet+54+4*index],'little')
   data[start+16*i:start+16*i+16]=value.to_bytes(16,'big')
 return call(target,data[:meta.get('input_bytes',len(data))])
def compare_kernel(packet,label):
 before=bytes.fromhex(kernel_call(old_address,packet,old_meta,baseline)[2:])
 after=bytes.fromhex(kernel_call(new_address,packet,new_meta,manifest)[2:])
 assert before[:288]==after[:288],label
 def decode(frame,meta,profile):
  abi=profile.get('context_abi','sparse-register-updates-v1')
  assert abi in ('sparse-register-updates-v1','dense-register-results-v2')
  stride=32 if abi=='dense-register-results-v2' else 64
  writes=meta['write_registers'];assert len(frame)==288+stride*len(writes)
  decoded={}
  for j,register in enumerate(writes):
   offset=32*register;at=288+stride*j
   if stride==64:
    assert int.from_bytes(frame[at:at+32],'big')==offset;at+=32
   assert offset not in decoded and offset<c.registers*32
   decoded[offset]=frame[at:at+32]
  return decoded
 expected=decode(before,old_meta,baseline);actual=decode(after,new_meta,manifest)
 for offset,value in actual.items():
  assert value==expected.get(offset,packet[offset:offset+32]),(label,offset)
for case in range(64):
 for reg in range(c.registers):context[32*reg:32*reg+32]=word(sum(rng.randrange(m.P)<<(32*j) for j in range(4)))
 for index in indices:
  for j in range(4):context[c.packet+38+4*(index+j):c.packet+42+4*(index+j)]=rng.randrange(1,m.P).to_bytes(4,'little')
 apply_facts(context)
 compare_kernel(context,case)
for index in indices:
 context[c.packet+38+4*index:c.packet+54+4*index]=(1).to_bytes(16,'little')
apply_facts(context)
compare_kernel(context,'all unbound inverse inputs one')
unbound=[ix for ix in indices if not all(str(ix+j) in facts['fields'] for j in range(4))]
assert len(unbound)>=3
for index in [unbound[0],unbound[len(unbound)//2],unbound[-1]]:
 packet=bytearray(context);at=c.packet+38+4*index;packet[at:at+16]=bytes(16)
 for target,meta,profile in [(old_address,old_meta,baseline),(new_address,new_meta,manifest)]:
  try:kernel_call(target,packet,meta,profile)
  except RuntimeError as e:assert 'revert' in str(e),str(e)
  else:raise AssertionError('accepted zero denominator')
report={'poseidon_sponge_cases':150,'poseidon_lengths':[0,1,7,8,9,15,16,17,223,224,225],'random_inverse_kernel_cases':64,'unbound_inverse_inputs_one_cases':1,'inverses_per_kernel':171,'zero_denominator_positions':3,'respects_prior_assertion_facts':True,'seed':8391031}
report['inversion_comparison_scope']=comparison_scope
report['original_instruction_span']=[lo,hi]
report['hash_optimizer']=hash_kernel['optimizer']
report['hash_optimizer_runs']=hash_kernel['optimizer_runs']
report['loop_partial_rounds']=selected_manifest.get('loop_partial_rounds',False)
report['tracked_partial_sum']=selected_manifest.get('tracked_partial_sum',False)
(out/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
