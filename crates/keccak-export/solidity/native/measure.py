#!/usr/bin/env python3
"""Validate native checkpoints, then measure a cold full proof on local Anvil.

Chain 31337, no code-size override. Diagnostic mode permits larger transactions;
--capped-osaka requires an enforced transaction cap and a successful receipt.
All deployments use the node's local test account, never an attached wallet.
"""
import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
sys.dont_write_bytecode=True
from reference import Reference, kh


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build',type=Path,required=True)
    ap.add_argument('--fixtures',type=Path,required=True)
    ap.add_argument('--artifact',type=Path,help='legacy Forge artifact; current builds use their independently pinned component artifacts')
    ap.add_argument('--rpc',default='http://127.0.0.1:18600')
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--skip-checkpoints',action='store_true')
    ap.add_argument('--profile-whir',action='store_true',help='also measure the auxiliary PCS using the checked intermediate context')
    ap.add_argument('--hash-dictionary',action='store_true',help='measure lossless full-hash dictionary transport; checkpoints still use the original raw packet')
    ap.add_argument('--zero-runs',action='store_true',help='measure lossless mode-3 field zero runs plus the full-hash dictionary')
    ap.add_argument('--zero-run-minimum',type=int,default=8,help='encoder-only minimum zero fields per run (default 8)')
    ap.add_argument('--deployments',type=Path,help='node-specific kernel deployment cache; default is BUILD/deployments.json')
    ap.add_argument('--verification-gas-limit',type=int,help='actual gas limit for the complete verification transaction')
    ap.add_argument('--capped-osaka',action='store_true',help='require Osaka and a verified enforced transaction cap; submit complete verification at or below 16,777,216 gas')
    a=ap.parse_args()
    if a.profile_whir and a.skip_checkpoints:ap.error('--profile-whir requires checked intermediate state')
    if a.zero_run_minimum<1:ap.error('zero-run-minimum must be positive')
    cap=16_777_216
    verification_gas=a.verification_gas_limit if a.verification_gas_limit is not None else cap if a.capped_osaka else 5_000_000_000
    if not 0<verification_gas<1<<64:ap.error('verification-gas-limit must be positive and fit uint64')
    if a.capped_osaka and verification_gas>cap:ap.error('capped Osaka verification must use at most 16,777,216 gas')
    assert urllib.parse.urlparse(a.rpc).hostname in ('127.0.0.1','localhost')
    def rpc(method,params):
        request=urllib.request.Request(a.rpc,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=300) as response:r=json.load(response)
        if 'error' in r:raise RuntimeError(r['error'])
        return r['result']
    assert int(rpc('eth_chainId',[]),16)==31337,'local benchmark only'
    account=rpc('eth_accounts',[])[0]
    node=rpc('anvil_nodeInfo',[])
    cap_rejection=None
    if a.capped_osaka:
        assert node['hardFork'].lower()=='osaka','capped acceptance requires Osaka'
        assert int(node['environment']['gasLimit'],16)>cap+1,'block limit must not be mistaken for the per-transaction cap'
        # This empty self-transfer must fail before entering the transaction
        # pool. A funded local account and a larger block limit isolate the
        # transaction-cap check from balance, execution and block-limit errors.
        try:
            rpc('eth_sendTransaction',[{'from':account,'to':account,'value':'0x0','gas':hex(cap+1),'gasPrice':hex(1_000_000_000)}])
        except RuntimeError as error:
            message=str(error).lower()
            assert 'gas' in message and ('limit' in message or 'cap' in message),'unexpected over-cap rejection'
            cap_rejection=str(error)
        else:
            raise AssertionError('node accepted a transaction above the Osaka cap')
    word=lambda n:n.to_bytes(32,'big')
    def send(data,to=None,gas=10_000_000,require_success=True):
        tx={'from':account,'data':'0x'+data.hex(),'gas':hex(gas),'gasPrice':hex(1_000_000_000)}
        if to:tx['to']=to
        h=rpc('eth_sendTransaction',[tx])
        for _ in range(200):
            receipt=rpc('eth_getTransactionReceipt',[h])
            if receipt:
                if require_success:assert int(receipt['status'],16)==1,('transaction reverted',h)
                return receipt
            time.sleep(.05)
        raise RuntimeError('receipt timeout')
    def call(address,data):
        budget=cap if a.capped_osaka else 5_000_000_000
        return bytes.fromhex(rpc('eth_call',[{'to':address,'data':'0x'+data.hex(),'gas':hex(budget)},'latest'])[2:])
    manifest=json.loads((a.build/'native.json').read_text())
    if a.zero_runs and not manifest.get('zero_run_fields'):ap.error('selected build does not accept mode-3 field runs')
    assert manifest['context_abi'] in ('sparse-register-updates-v1','dense-register-results-v2'),'unknown native context ABI'
    old_program=(a.fixtures/'compiled/program.bin').read_bytes()
    assert manifest['source_program_hash']=='0x'+kh(old_program).hex()
    packet=(a.fixtures/'raw.bin').read_bytes()
    output=bytes.fromhex(json.loads((a.fixtures/'compiled/statement.json').read_text())['output_digest'][2:])
    deployed=[]
    deployments=a.deployments or a.build/'deployments.json'
    deployments.parent.mkdir(parents=True,exist_ok=True)
    if deployments.exists():deployed=json.loads(deployments.read_text())
    addresses=[];deploy_gas=0
    for i,k in enumerate(manifest['kernels']):
        creation=bytes.fromhex(k['bytecode']);runtime=bytes.fromhex(k['runtime'])
        assert len(runtime)<=24576 and len(creation)<=49152
        cached=deployed[i] if i<len(deployed) else None
        code=rpc('eth_getCode',[cached['address'],'latest']) if cached else '0x'
        if not cached or kh(bytes.fromhex(code[2:]))!=bytes.fromhex(k['code_hash'][2:]):
            receipt=send(creation);cached={'address':receipt['contractAddress'],'gas':int(receipt['gasUsed'],16),'code_hash':k['code_hash']}
            if i<len(deployed):deployed[i]=cached
            else:deployed.append(cached)
            deployments.write_text(json.dumps(deployed,indent=2)+'\n')
        addresses.append(cached['address']);deploy_gas+=cached['gas']
    print(f'deployed {len(addresses)} native kernels; total deployment gas {deploy_gas}',flush=True)
    if not a.skip_checkpoints:
        approved=json.loads((a.fixtures/'compiled/program.json').read_text())
        ref=Reference(approved,packet,output)
        prefix=manifest['context_prefix_bytes'];reg_bytes=manifest['registers']*32
        original_context_bytes=prefix+32+len(packet)
        context=bytearray(manifest.get('context_bytes',original_context_bytes))
        context[reg_bytes:reg_bytes+32]=ref.t.digest
        context[reg_bytes+288:reg_bytes+320]=output
        context[prefix:prefix+32]=word(len(packet));context[prefix+32:original_context_bytes]=packet
        for i,index in enumerate(manifest.get('proof_cache_indices') or []):
            value=int.from_bytes(packet[38+4*index:54+4*index],'little')
            at=original_context_bytes+16*i;context[at:at+16]=value.to_bytes(16,'big')
        for address,k in zip(addresses,manifest['kernels']):
            ref.run(k['start'],k['end'])
            result=call(address,context)
            abi=manifest['context_abi']
            assert abi in ('sparse-register-updates-v1','dense-register-results-v2'),'unknown native context ABI'
            stride=32 if abi=='dense-register-results-v2' else 64
            expected=k['write_registers']
            assert expected==sorted(set(expected)) and all(0<=r<manifest['registers'] for r in expected)
            assert len(result)==288+stride*len(expected)
            context[reg_bytes:reg_bytes+288]=result[:288]
            for j,register in enumerate(expected):
                at=288+stride*j
                if stride==64:
                    assert int.from_bytes(result[at:at+32],'big')==32*register
                    at+=32
                context[32*register:32*register+32]=result[at:at+32]
            ref.check(context[:prefix],k.get('live_registers_after'))
        rust_vector=json.loads((a.fixtures/'whir.json').read_text())
        rust=rust_vector['entry']
        assert ref.t.digest.hex()==rust['digest'].removeprefix('0x')
        assert ref.t.buffer.hex()==rust['buffered'].removeprefix('0x')
        assert ref.t.left==rust['wordsLeft']
        from compile import Compiler
        from wire import parse
        approved_compiler=Compiler(approved,old_program)
        _,root_refs,stripes,point_refs,_=parse(approved_compiler.tail)
        def actual_value(value):
            return int.from_bytes(context[32*value:32*value+32],'big') if value<0x10000000 else ref.get(value)
        assert [actual_value(value) for value in point_refs]==[int(value,16) for value in rust_vector['point']]
        assert [actual_value(value) for value in root_refs]==[int(value,16) for value in rust_vector['roots']]
        assert stripes==rust_vector['stripes']
        (a.build/'checkpoint-validation.json').write_text(json.dumps({
            'kernels_checked':len(addresses),
            'registers_per_checkpoint':len(ref.regs) if not manifest.get('dead_arithmetic_operations') else None,
            'available_registers':len(ref.regs),
            'live_register_counts':[len(k.get('live_registers_after',ref.regs)) for k in manifest['kernels']],
            'all_registers_match_python_reference':not bool(manifest.get('dead_arithmetic_operations')),
            'all_semantically_live_registers_match_python_reference':True,
            'whir_point_and_roots_match_rust_export':True,
            'transcript_matches_authenticated_rust_export':True},indent=2)+'\n')
        print('every native checkpoint matches independent reference; final transcript matches Rust',flush=True)
    if manifest.get('entry_creation_hash'):
        artifact=json.loads((a.build/'entry-artifact.json').read_text())
        creation_code=bytes.fromhex(artifact['bytecode']['object'].removeprefix('0x'))
        assert manifest['entry_creation_hash']=='0x'+kh(creation_code).hex(),'entry creation artifact differs from pinned build'
        assert (a.build/'entry-creation.bin').read_bytes()==creation_code
    else:
        if a.artifact is None:ap.error('--artifact is required for legacy builds')
        artifact=json.loads(a.artifact.read_text())
    runtime=bytes.fromhex(artifact['deployedBytecode']['object'].removeprefix('0x'))
    assert len(runtime)<=24576,'entry runtime exceeds EIP-170'
    if manifest.get('whir_creation_hash'):
        tail_artifact=json.loads((a.build/'whir-artifact.json').read_text())
        assert manifest['whir_creation_hash']=='0x'+kh(bytes.fromhex(tail_artifact['bytecode']['object'])).hex()
        assert (a.build/'whir-creation.bin').read_bytes()==bytes.fromhex(tail_artifact['bytecode']['object'])
    else:
        if a.artifact is None:ap.error('--artifact is required for legacy WHIR builds')
        tail_path=a.artifact.parent.parent/'CompiledWhirVerifier.sol/CompiledWhirVerifier.json'
        if not tail_path.exists():tail_path=a.artifact.with_name('CompiledWhirVerifier.json')
        tail_artifact=json.loads(tail_path.read_text())
    tail_runtime=bytes.fromhex(tail_artifact['deployedBytecode']['object'].removeprefix('0x'))
    tail_creation=bytes.fromhex(tail_artifact['bytecode']['object'].removeprefix('0x'))
    assert len(tail_runtime)<=24576 and len(tail_creation)<=49152,'WHIR tail code size limit'
    if 'approved_whir_runtime_hash' in manifest:
        assert manifest['approved_whir_runtime_hash']=='0x'+kh(tail_runtime).hex(),'PCS artifact differs from the exact pinned runtime'
    tail_receipt=send(tail_creation)
    tail=tail_receipt['contractAddress'];tail_gas=int(tail_receipt['gasUsed'],16)
    closing=None;closing_gas=0;closing_runtime_bytes=None
    if manifest.get('closing_module_runtime_hash'):
        if manifest.get('closing_creation_hash'):
            closing_artifact=json.loads((a.build/'closing-artifact.json').read_text())
            assert manifest['closing_creation_hash']=='0x'+kh(bytes.fromhex(closing_artifact['bytecode']['object'])).hex()
            assert (a.build/'closing-creation.bin').read_bytes()==bytes.fromhex(closing_artifact['bytecode']['object'])
        else:
            if a.artifact is None:ap.error('--artifact is required for legacy closing builds')
            closing_path=a.artifact.parent.parent/'NativeClosingEvaluator.sol/NativeClosingEvaluator.json'
            closing_artifact=json.loads(closing_path.read_text())
        closing_runtime=bytes.fromhex(closing_artifact['deployedBytecode']['object'].removeprefix('0x'))
        closing_creation=bytes.fromhex(closing_artifact['bytecode']['object'].removeprefix('0x'))
        assert len(closing_runtime)<=24576 and len(closing_creation)<=49152
        assert '0x'+kh(closing_runtime).hex()==manifest['closing_module_runtime_hash']
        closing_receipt=send(closing_creation);closing=closing_receipt['contractAddress'];closing_gas=int(closing_receipt['gasUsed'],16)
        closing_runtime_bytes=len(closing_runtime)
    constructor=word(96 if closing else 64)+word(int(tail,16))+(word(int(closing,16)) if closing else b'')+word(len(addresses))+b''.join(word(int(x,16)) for x in addresses)
    creation=bytes.fromhex(artifact['bytecode']['object'].removeprefix('0x'))+constructor
    assert len(creation)<=49152,'entry initcode exceeds EIP-3860'
    receipt=send(creation)
    root=receipt['contractAddress'];root_deploy_gas=int(receipt['gasUsed'],16)
    assert len(bytes.fromhex(rpc('eth_getCode',[root,'latest'])[2:]))==len(runtime),'entry runtime size differs from pinned artifact'
    assert call(root,kh(b'verifierProgramHash()')[:4])==bytes.fromhex(manifest['source_program_hash'][2:])
    table_runtime_bytes=None
    if 'approved_whir_runtime_hash' in manifest:
        count=call(root,kh(b'kernelCount()')[:4])
        assert int.from_bytes(count,'big')==len(addresses)
        table='0x'+call(root,kh(b'kernelTable()')[:4])[-20:].hex()
        table_code=bytes.fromhex(rpc('eth_getCode',[table,'latest'])[2:])
        assert table_code==b'\0'+b''.join(bytes.fromhex(address[2:]) for address in addresses),'kernel table bytes/order differ'
        table_runtime_bytes=len(table_code)
    submitted=packet
    if a.hash_dictionary or a.zero_runs:
        from transport import encode,decode,encode_zero_runs
        meta=json.loads((a.fixtures/'compiled/program.json').read_text())['metadata']
        submitted=encode_zero_runs(packet,meta['field_count'],meta['hash_count'],a.zero_run_minimum) if a.zero_runs else encode(packet,meta['field_count'],meta['hash_count'])
        assert decode(submitted,meta['field_count'],meta['hash_count'])==packet
    dynamic=word(len(submitted))+submitted+bytes((-len(submitted))%32)
    calldata=kh(b'verify(bytes,bytes32)')[:4]+word(64)+output+dynamic
    receipt=send(calldata,root,verification_gas,require_success=False)
    if int(receipt['status'],16)!=1:
        failure={'scope':'complete proof verification attempt; failed receipt is not a successful gas benchmark',
            'complete_verification_succeeded':False,'capped_osaka_receipt':False,
            'hardfork':node['hardFork'],'verification_transaction_gas_limit':verification_gas,
            'transaction_gas_used':int(receipt['gasUsed'],16),'receipt_status':receipt['status'],
            'transaction_hash':receipt['transactionHash'],'entry_address':root,
            'over_cap_transaction_rejected':cap_rejection,'ordinary_code_and_initcode_sizes_checked':True}
        a.out.write_text(json.dumps(failure,indent=2)+'\n')
        raise AssertionError(('verification transaction reverted at selected gas limit',receipt['transactionHash']))
    start=time.perf_counter();result=call(root,calldata);seconds=time.perf_counter()-start
    assert result==word(1),'full native verifier did not return true'
    tokens=calldata.count(0)+4*(len(calldata)-calldata.count(0));gas=int(receipt['gasUsed'],16)
    assert gas>21000+10*tokens,'execution decomposition requires receipt above floor'
    report={'workload':'complete approved terminal proof; supplied KoalaBear E4/Keccak parameters and wire packet',
        'entry_optimizer_runs':manifest.get('entry_optimizer_runs',1),
        'whir_optimizer_runs':manifest.get('whir_optimizer_runs',1),
        'closing_optimizer_runs':manifest.get('closing_optimizer_runs',1),
        'backend':f"local Anvil {node['hardFork']}; ordinary code/initcode sizes; "+('enforced transaction cap' if a.capped_osaka else 'diagnostic gas allowance'),
        'complete_verification_succeeded':True,'receipt_status':receipt['status'],
        'verification_transaction_gas_limit':verification_gas,
        'capped_osaka_receipt':a.capped_osaka,
        'over_cap_transaction_rejected':cap_rejection,
        'source_program_hash':manifest['source_program_hash'],'kernel_count':len(addresses),
        'context_abi':manifest['context_abi'],
        'kernel_input_register_words':sum(len(k['read_registers']) for k in manifest['kernels']),
        'kernel_return_register_words':sum(len(k['write_registers']) for k in manifest['kernels']),
        'all_kernel_runtimes_fit_eip170':True,'max_kernel_runtime_bytes':max(k['runtime_bytes'] for k in manifest['kernels']),
        'entry_runtime_bytes':len(runtime),'entry_initcode_bytes':len(creation),
        'kernel_table_runtime_bytes':table_runtime_bytes,'kernel_table_creation_included_in_entry_receipt':table_runtime_bytes is not None,
        'whir_runtime_bytes':len(tail_runtime),'whir_deployment_gas':tail_gas,
        'native_kernel_deployment_gas':deploy_gas,'entry_deployment_gas':root_deploy_gas,
        'closing_module_address':closing,'closing_module_runtime_bytes':closing_runtime_bytes,'closing_module_deployment_gas':closing_gas,
        'total_deployment_gas':deploy_gas+root_deploy_gas+tail_gas+closing_gas,
        'proof_packet_bytes':len(submitted),'expanded_proof_packet_bytes':len(packet),
        'transport':'field-zero-runs-hash-dictionary-v1' if a.zero_runs else 'full-hash-dictionary-v1' if a.hash_dictionary else 'raw',
        'zero_run_minimum':a.zero_run_minimum if a.zero_runs else None,
        'abi_calldata_bytes':len(calldata),'submitted_program_bytes':0,
        'ordinary_calldata_gas':4*tokens,'eip7623_floor':21000+10*tokens,
        'full_verification_transaction_gas':gas,'full_verification_execution_gas':gas-21000-4*tokens,
        'local_eth_call_seconds':seconds,'historical_interpreter_transaction_gas':99226413,
        'gas_reduction_fraction':1-gas/99226413,'eip7825_cap':cap,'receipt_gas_below_cap':gas<=cap,
        'fits_mainnet_transaction':a.capped_osaka and gas<=cap,
        'times_transaction_cap':gas/16777216,'entry_address':root,'whir_address':tail,'transaction_hash':receipt['transactionHash']}
    report['external_creation_transactions']=len(addresses)+2+int(bool(closing))
    report['total_contracts']=report['external_creation_transactions']+int(table_runtime_bytes is not None)
    if manifest.get('proof_cache_module'):
        cache_word=call(root,kh(b'proofCacheModule()')[:4]);assert len(cache_word)==32
        cache_address='0x'+cache_word[-20:].hex()
        cache_runtime=bytes.fromhex(rpc('eth_getCode',[cache_address,'latest'])[2:])
        assert '0x'+kh(cache_runtime).hex()==manifest['proof_cache_module']['runtime_hash']
        assert len(cache_runtime)==manifest['proof_cache_module']['runtime_bytes']<=24576
        report.update(proof_cache_module_address=cache_address,proof_cache_module_runtime_bytes=len(cache_runtime),
            proof_cache_creation_included_in_entry_receipt=True)
        report['total_contracts']+=1
    if manifest.get('native_closing_module'):
        driver_word=call(closing,kh(b'closingDriver()')[:4]);assert len(driver_word)==32
        driver_address='0x'+driver_word[-20:].hex()
        driver_runtime=bytes.fromhex(rpc('eth_getCode',[driver_address,'latest'])[2:])
        driver_manifest=manifest['native_closing_module']
        assert '0x'+kh(driver_runtime).hex()==driver_manifest['runtime_hash']
        assert len(driver_runtime)==driver_manifest['runtime_bytes']<=24576
        driver_creation=(a.build/'native-closing-creation.bin').read_bytes()
        assert len(driver_creation)<=49152 and '0x'+kh(driver_creation).hex()==driver_manifest['creation_hash']
        report.update(native_closing_driver_address=driver_address,native_closing_driver_runtime_bytes=len(driver_runtime),
            native_closing_driver_creation_included_in_closing_receipt=True)
        report['total_contracts']+=1
    if a.profile_whir:
        pcs_context=context[:manifest['packet_offset']+len(packet)]
        signature=b'verifyContext(bytes,address)' if closing else b'verifyContext(bytes)'
        auxiliary=kh(signature)[:4]+word(64 if closing else 32)+(word(int(closing,16)) if closing else b'')+word(len(pcs_context))+pcs_context+bytes((-len(pcs_context))%32)
        assert call(tail,auxiliary)==word(1)
        component=send(auxiliary,tail,cap if a.capped_osaka else 5_000_000_000)
        aux_gas=int(component['gasUsed'],16)
        aux_tokens=auxiliary.count(0)+4*(len(auxiliary)-auxiliary.count(0))
        floor=21000+10*aux_tokens
        report['auxiliary_whir_profile']={
            'scope':'PCS only with the checked intermediate context; not complete machine-proof verification',
            'transaction_gas':aux_gas,'ordinary_calldata_gas':4*aux_tokens,'eip7623_floor':floor,
            'execution_gas':aux_gas-21000-4*aux_tokens if aux_gas>floor else None,
            'execution_upper_bound_if_floor_binds':floor-21000-4*aux_tokens if aux_gas==floor else None,
            'transaction_hash':component['transactionHash']}
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
