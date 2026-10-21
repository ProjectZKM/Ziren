#!/usr/bin/env python3
"""Measure a complete reference verifier on a localhost Anvil chain.

Run Anvil with Prague rules, a deliberately relaxed block limit, and
--no-request-size-limit. The result is compared with mainnet's transaction cap;
relaxing a local benchmark does not make the call deployable on mainnet.
"""
import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rpc',default='http://127.0.0.1:18598')
    p.add_argument('--fixtures',type=Path,required=True)
    p.add_argument('--artifact',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    assert urllib.parse.urlparse(a.rpc).hostname in ('127.0.0.1','localhost')
    def rpc(method,params):
        request=urllib.request.Request(a.rpc,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=300) as response:r=json.load(response)
        if 'error' in r:raise RuntimeError(r['error'])
        return r['result']
    assert int(rpc('eth_chainId',[]),16)==31337,'local benchmark only'
    account=rpc('eth_accounts',[])[0]
    program=(a.fixtures/'compiled/program.bin').read_bytes()
    proof=(a.fixtures/'raw.bin').read_bytes()
    output=bytes.fromhex(json.loads((a.fixtures/'compiled/statement.json').read_text())['output_digest'][2:])
    artifact=json.loads(a.artifact.read_text())
    word=lambda x:x.to_bytes(32,'big')
    program_hash=rpc('web3_sha3',['0x'+program.hex()])
    def send(data,to=None):
        tx={'from':account,'data':'0x'+data.hex(),'gas':hex(5_000_000_000),'gasPrice':hex(1_000_000_000)}
        if to:tx['to']=to
        h=rpc('eth_sendTransaction',[tx])
        for _ in range(100):
            receipt=rpc('eth_getTransactionReceipt',[h])
            if receipt:
                assert int(receipt['status'],16)==1,f'verification transaction reverted {h}'
                return receipt
            time.sleep(.05)
        raise RuntimeError('receipt timeout')
    creation=bytes.fromhex(artifact['bytecode']['object'].removeprefix('0x'))+bytes.fromhex(program_hash[2:])
    deployed=send(creation)
    dynamic=lambda b:word(len(b))+b+bytes((-len(b))%32)
    selector=bytes.fromhex(artifact['methodIdentifiers']['verify(bytes,bytes,bytes32)'])
    program_tail=dynamic(program)
    call=selector+word(96)+word(96+len(program_tail))+output+program_tail+dynamic(proof)
    start=time.perf_counter()
    result=rpc('eth_call',[{'from':account,'to':deployed['contractAddress'],'data':'0x'+call.hex(),'gas':hex(5_000_000_000)},'latest'])
    seconds=time.perf_counter()-start
    assert result=='0x'+word(1).hex(),'complete verification did not return true'
    receipt=send(call,deployed['contractAddress'])
    zero=call.count(0);tokens=zero+4*(len(call)-zero);floor=21000+10*tokens
    charged=int(receipt['gasUsed'],16)
    assert charged>floor,'execution estimate requires transaction above floor'
    report={'workload':'complete approved KoalaBear-Keccak terminal proof; supplied fixed trusted profile',
            'backend':'local Anvil Prague; block gas limit relaxed; EIP-7825 cap compared separately',
            'program_hash':program_hash,'program_bytes':len(program),'proof_packet_bytes':len(proof),'abi_calldata_bytes':len(call),
            'zero_calldata_bytes':zero,'nonzero_calldata_bytes':len(call)-zero,'calldata_tokens':tokens,
            'standard_calldata_gas':4*tokens,'eip7623_floor':floor,'full_verification_transaction_gas':charged,
            'full_verification_execution_gas':charged-21000-4*tokens,'local_eth_call_seconds':seconds,
            'eip7825_cap':16777216,'fits_mainnet_transaction':charged<=16777216,
            'times_transaction_cap':charged/16777216,'runtime_bytes':len(artifact['deployedBytecode']['object'].removeprefix('0x'))//2,
            'deployment_gas':int(deployed['gasUsed'],16),'transaction_hash':receipt['transactionHash']}
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
