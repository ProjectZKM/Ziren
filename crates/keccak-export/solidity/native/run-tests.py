#!/usr/bin/env python3
"""Run complete native/reference equivalence tests with external artifacts."""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--build',type=Path,required=True)
ap.add_argument('--fixtures',type=Path,required=True)
a,extra=ap.parse_known_args()
root=Path(__file__).resolve().parent
assert not a.build.resolve().is_relative_to(root.parents[3]), 'artifacts must stay outside repository'
manifest=json.loads((a.build/'native.json').read_text())
artifacts=a.build/'kernels';artifacts.mkdir(exist_ok=True)
names=[]
for k in manifest['kernels']:
    names.append(k['name'])
    (artifacts/(k['name']+'.bin')).write_bytes(bytes.fromhex(k['bytecode']))
(a.build/'deployment-files.json').write_text(json.dumps({'count':len(names),'names':names}))
approved_program=json.loads((a.fixtures/'compiled/program.json').read_text())
from transport import encode, decode, encode_zero_runs
meta=approved_program['metadata']
raw=(a.fixtures/'raw.bin').read_bytes()
packed=encode(raw,meta['field_count'],meta['hash_count'])
assert decode(packed,meta['field_count'],meta['hash_count'])==raw
(a.build/'hash-dictionary.bin').write_bytes(packed)
(a.build/'hash-dictionary.json').write_text(json.dumps({'prefix':38+4*meta['field_count'],'hashes':meta['hash_count']}))
import importlib.util
spec=importlib.util.spec_from_file_location('native_codegen',root/'compile.py')
generator=importlib.util.module_from_spec(spec);spec.loader.exec_module(generator)
from wire import parse
compiler=generator.Compiler(approved_program,(a.fixtures/'compiled/program.bin').read_bytes())
proof=parse(compiler.tail)[4]
path_mutations=[]
for group in proof['openings']:
    first=group[0]['path'][0]&0x0fffffff;last=group[-1]['path'][-1]&0x0fffffff
    path_mutations.extend([38+4*meta['field_count']+32*first,38+4*meta['field_count']+32*last+31])
(a.build/'merkle-path-mutations.json').write_text(json.dumps({'count':len(path_mutations),'byte_offsets':path_mutations}))
leaf_fields=[]
for group in proof['openings']:
    for leaf in (group[0],group[-1]):
        for ref in (leaf['values'][0][0],leaf['values'][-1][-1]):
            assert ref&0xf0000000==0x40000000
            leaf_fields.append(ref&0x0fffffff)
(a.build/'leaf-field-mutations.json').write_text(json.dumps({'count':len(leaf_fields),'fields':leaf_fields}))
approved=approved_program['schema']
shard=approved['proof']['jagged_shard_proof'];bundle=approved['bundle']
def first_field(extension):return extension['value'][0]['f']
mutations=[
    first_field(shard['zerocheck_proof']['univariate_polys'][0]['coefficients'][0]),
    first_field(shard['opened_values']['chips'][1]['main']['local'][0]),
    first_field(shard['opened_values']['chips'][4]['main']['local'][0]),
    first_field(bundle['reduction']['q_at_z']),
    first_field(bundle['reduction']['rounds'][0]['evals'][0]),
    first_field(shard['opened_values']['chips'][0]['quotient'][0][0]),
]
denominator=shard['logup_gkr_proof']['circuit_output']['denominator'][0]['value']
assert [x['f'] for x in denominator]==list(range(denominator[0]['f'],denominator[0]['f']+4))
direct_fields=[next(op[2]&0x0fffffff for op in approved_program['ops'] if op[0]==opcode and op[2]&0xf0000000==tag)
               for opcode,tag in [(10,0x40000000),(11,0x20000000)]]
fact_fields=[]
if manifest.get('assertion_facts'):
    known=sorted(map(int,manifest['kernels'][-1]['constant_preconditions']['fields']))
    fact_fields=sorted(set(known[:4]+[known[len(known)*j//4] for j in (1,2,3)]+known[-1:]))
    assert all(0<=field<meta['field_count'] for field in fact_fields)
(a.build/'native-mutations.json').write_text(json.dumps({'fields':mutations,'zero_denominator':denominator[0]['f'],
                                                       'direct_observation_fields':direct_fields,
                                                       'assertion_fact_count':len(fact_fields),'assertion_fact_fields':fact_fields}))
tests=a.build/'test';tests.mkdir(exist_ok=True)
if manifest.get('contiguous_results'):
    from wire import dense_driver_source
    dense_test=(root/'NativeDenseFrames.t.sol.in').read_text()
    assert dense_test.count('DENSE_DRIVER')==1
    (tests/'NativeDenseFrames.t.sol').write_text(dense_test.replace('DENSE_DRIVER',dense_driver_source([[0,1,3],[1,4]],5)))
native_test=(root/'NativeTerminal.t.sol.in').read_text()
if manifest.get('closing_module_runtime_hash'):
    native_test=native_test.replace('contract NativeTerminalTest {','import {NativeClosingEvaluator} from "../src/NativeClosingEvaluator.sol";\ncontract NativeTerminalTest {\n    NativeClosingEvaluator closing;')
    native_test=native_test.replace('        tail=new CompiledWhirVerifier();','        closing=new NativeClosingEvaluator();\n        require(address(closing).code.length<=24576,"closing EIP170 violation");\n        tail=new CompiledWhirVerifier();')
    marker='new CompiledTerminalVerifier('
    at=0
    while True:
        start=native_test.find(marker,at)
        if start<0:break
        end=start+len(marker);depth=1
        while depth:
            depth+=(native_test[end]=='(')-(native_test[end]==')');end+=1
        native_test=native_test[:end-1]+',address(closing)'+native_test[end-1:]
        at=end+len(',address(closing)')
    closing_test='''
    function testClosingCodeHashBinding() public {
        try new CompiledTerminalVerifier(modules,address(tail),modules[0]) returns(CompiledTerminalVerifier){revert("wrong closing module accepted");}
        catch(bytes memory error){require(keccak256(error)==keccak256(abi.encodeWithSignature("Error(string)","closing code hash")),"wrong constructor failure");}
        bytes memory fake=new bytes(CONTEXT_BYTES);
        (bool ok,bytes memory error)=address(tail).staticcall(abi.encodeCall(tail.verifyContext,(fake,modules[0])));
        require(!ok && keccak256(error)==keccak256(abi.encodeWithSignature("Error(string)","closing code hash")),"tail accepted unapproved closing module");
    }
'''.replace('CONTEXT_BYTES',str(manifest['packet_offset']+manifest['proof_bytes']))
    end=native_test.rfind('}');native_test=native_test[:end]+closing_test+native_test[end:]
if manifest.get('entry_creation_hash'):
    # Test the exact independently compiled entry creation bytecode. Keeping
    # Forge's tail/math settings at runs=1 preserves their pinned code hashes.
    from reference import kh
    entry_creation=(a.build/'entry-creation.bin').read_bytes()
    assert '0x'+kh(entry_creation).hex()==manifest['entry_creation_hash']
    artifact=json.loads((a.build/'entry-artifact.json').read_text())
    assert bytes.fromhex(artifact['bytecode']['object'])==entry_creation
    native_test=native_test.replace('new CompiledTerminalVerifier(','this.deployNative(')
    closing=bool(manifest.get('closing_module_runtime_hash'))
    deploy_test='''
    function deployNative(address[] memory selected,address whirCLOSING_PARAMETER) external returns(CompiledTerminalVerifier result){
        bytes memory code=bytes.concat(vm.readFileBinary(string.concat(vm.envString("NATIVE_BUILD"),"/entry-creation.bin")),abi.encode(selected,whirCLOSING_ARGUMENT));
        require(code.length<=49152,"entry initcode violation");
        address deployed;
        assembly("memory-safe"){
            deployed:=create(0,add(code,32),mload(code))
            if iszero(deployed){let at:=mload(0x40) returndatacopy(at,0,returndatasize()) revert(at,returndatasize())}
        }
        result=CompiledTerminalVerifier(deployed);
    }
'''.replace('CLOSING_PARAMETER',',address selectedClosing' if closing else '').replace('CLOSING_ARGUMENT',',selectedClosing' if closing else '')
    end=native_test.rfind('}');native_test=native_test[:end]+deploy_test+native_test[end:]
    for component,statement,replacement in [
        ('whir','tail=new CompiledWhirVerifier();','tail=CompiledWhirVerifier(deploySelected("whir-creation.bin"));'),
        ('closing','closing=new NativeClosingEvaluator();','closing=NativeClosingEvaluator(deploySelected("closing-creation.bin"));')]:
        if not manifest.get(component+'_creation_hash'):continue
        bytecode=(a.build/(component+'-creation.bin')).read_bytes()
        assert '0x'+kh(bytecode).hex()==manifest[component+'_creation_hash']
        artifact=json.loads((a.build/(component+'-artifact.json')).read_text())
        assert bytes.fromhex(artifact['bytecode']['object'])==bytecode
        assert native_test.count(statement)==1
        native_test=native_test.replace(statement,replacement,1)
    helper='''
    function deploySelected(string memory name) private returns(address result){
        bytes memory code=vm.readFileBinary(string.concat(vm.envString("NATIVE_BUILD"),"/",name));
        require(code.length<=49152,"auxiliary initcode violation");
        assembly("memory-safe"){
            result:=create(0,add(code,32),mload(code))
            if iszero(result){let at:=mload(0x40) returndatacopy(at,0,returndatasize()) revert(at,returndatasize())}
        }
    }
'''
    end=native_test.rfind('}');native_test=native_test[:end]+helper+native_test[end:]
if manifest.get('proof_cache_module'):
    native_test=native_test.replace('import {CompiledTerminalVerifier}', 'import {NativeProofCache} from "../src/NativeProofCache.sol";\nimport {CompiledTerminalVerifier}',1)
    compiler.prepare_proof_cache()
    cache_test='''
    function testConstructorCacheModuleMatchesReference() public view {
        address cache=nativeVerifier.proofCacheModule();
        require(cache.codehash==CACHE_HASH && cache.code.length==CACHE_CODE_BYTES,"cache runtime binding");
        bytes memory rawPacket=packet;uint256 rawLength=rawPacket.length;bytes memory context=new bytes(32+rawLength+CACHE_BYTES);
        assembly("memory-safe"){
            mstore(add(context,32),rawLength)
            mcopy(add(context,64),add(rawPacket,32),rawLength)
        }
        NativeProofCache.populate(context,32,FIELD_COUNT,hex"CACHE_RANGES");
        bytes memory fields=new bytes(4*FIELD_COUNT);
        assembly("memory-safe"){mcopy(add(fields,32),add(rawPacket,70),mload(fields))}
        (bool ok,bytes memory native)=cache.staticcall(fields);
        require(ok && native.length==CACHE_BYTES,"cache return shape");
        bytes32 expected;
        assembly("memory-safe"){expected:=keccak256(add(add(context,64),rawLength),CACHE_BYTES)}
        require(keccak256(native)==expected,"cache byte mismatch");
        (ok,)=cache.staticcall("");require(!ok,"cache accepted invalid input length");
    }
'''
    for before,after in [('CACHE_HASH',manifest['proof_cache_module']['runtime_hash']),('CACHE_CODE_BYTES',str(manifest['proof_cache_module']['runtime_bytes'])),('CACHE_BYTES',str(16*len(compiler.proof_cache_indices)+16)),('FIELD_COUNT',str(compiler.meta['field_count'])),('CACHE_RANGES',compiler.proof_cache_ranges.hex())]:cache_test=cache_test.replace(before,after)
    end=native_test.rfind('}');native_test=native_test[:end]+cache_test+native_test[end:]
if manifest.get('zero_run_fields'):
    zero_packet=encode_zero_runs(raw,meta['field_count'],meta['hash_count'])
    assert decode(zero_packet,meta['field_count'],meta['hash_count'])==raw
    (a.build/'zero-runs.bin').write_bytes(zero_packet)
    at=38;done=0;first_zero=None
    while done<meta['field_count']:
        command=int.from_bytes(zero_packet[at:at+2],'big');at+=2;count=command&0x7fff
        if command&0x8000:at+=4*count
        elif first_zero is None:first_zero=done
        done+=count
    assert first_zero is not None and int.from_bytes(zero_packet[at:at+2],'big')&0x8000
    (a.build/'zero-run-shape.json').write_text(json.dumps({'first_hash_literal':at+2}))
    fields=sorted(set(leaf_fields+[first_zero]))
    for i,(field,value) in enumerate((field,value) for field in fields for value in (0x7f000001,0xffffffff)):
        changed=bytearray(raw);changed[38+4*field:42+4*field]=value.to_bytes(4,'little')
        (a.build/f'zero-run-invalid-{i}.bin').write_bytes(encode_zero_runs(bytes(changed),meta['field_count'],meta['hash_count']))
    count=2*len(fields)
    added='''
    function testZeroRunCompleteProofAndMalformedFrames() public {
        string memory build=vm.envString("NATIVE_BUILD");
        bytes memory packed=vm.readFileBinary(string.concat(build,"/zero-runs.bin"));
        require(nativeVerifier.verify(packed,digest),"zero-run full proof");
        rejectNative(packed,bytes32(uint256(digest)^1));
        rejectNative(bytes.concat(packed,hex"00"),digest);
        bytes memory bad=bytes.concat(packed);assembly("memory-safe"){mstore(bad,sub(mload(bad),1))}rejectNative(bad,digest);
        bad=bytes.concat(packed);bad[6]^=0x01;rejectNative(bad,digest);
        bad=bytes.concat(packed);bad[38]=0;bad[39]=0;rejectNative(bad,digest);
    }
    function testZeroRunNoncanonicalFieldsRejectedBeforeKernelCalls() public {
        string memory build=vm.envString("NATIVE_BUILD");
        for(uint256 i;i<INVALID_COUNT;++i){
            bytes memory bad=vm.readFileBinary(string.concat(build,"/zero-run-invalid-",vm.toString(i),".bin"));
            (bool ok,bytes memory error)=address(nativeVerifier).staticcall(abi.encodeCall(nativeVerifier.verify,(bad,digest)));
            require(!ok && error.length==4 && bytes4(error)==bytes4(keccak256("InvalidFieldBuffer()")),"zero-run canonicality was not checked before kernels");
        }
    }
    function testZeroRunHashMutationRejected() public {
        string memory build=vm.envString("NATIVE_BUILD");
        bytes memory bad=vm.readFileBinary(string.concat(build,"/zero-runs.bin"));
        uint256 at=vm.parseJsonUint(vm.readFile(string.concat(build,"/zero-run-shape.json")),".first_hash_literal");
        bad[at]^=0x01;rejectNative(bad,digest);
    }
'''.replace('INVALID_COUNT',str(count))
    end=native_test.rfind('}');native_test=native_test[:end]+added+native_test[end:]
(tests/'NativeTerminal.t.sol').write_text(native_test)
if manifest.get('packed_canonical'):
    (tests/'NativeCanonical.t.sol').write_text('''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {KoalaBear as F} from "../src/KoalaBear.sol";
import {ReferenceKoalaBear as R} from "../src/ReferenceKoalaBear.sol";
contract NativeCanonicalTest {
    function testFuzzPackedCanonicalMatchesOriginal(uint256 value,bytes32 seed) public pure {
        require(F.canonical(value)==R.canonical(value),"full word");
        uint256 low=uint128(value);
        require(F.canonical(low)==R.canonical(low),"arbitrary lanes");
        uint256 valid;
        for(uint256 i;i<4;++i)valid|=uint256(uint32(uint256(keccak256(abi.encode(seed,i))))%F.P)<<(32*i);
        require(F.canonical(valid) && R.canonical(valid),"canonical vector");
        for(uint256 i;i<4;++i){
            uint256 bad=(valid&~(uint256(type(uint32).max)<<(32*i)))|(uint256(F.P)<<(32*i));
            require(!F.canonical(bad) && !R.canonical(bad),"single invalid lane");
        }
    }
    function testPackedCanonicalAllLaneBoundaries() public pure {
        uint256[8] memory edges=[uint256(0),1,F.P-1,F.P,F.P+1,0x7fffffff,0x80000000,0xffffffff];
        for(uint256 lane;lane<4;++lane)for(uint256 i;i<8;++i){
            uint256 a=edges[i]<<(32*lane);
            require(F.canonical(a)==R.canonical(a),"isolated boundary");
            uint256 allMax=uint256(0xffffffff)|(uint256(0xffffffff)<<32)|(uint256(0xffffffff)<<64)|(uint256(0xffffffff)<<96);
            a|=allMax&~(uint256(0xffffffff)<<(32*lane));
            require(F.canonical(a)==R.canonical(a),"neighbor carry");
        }
        require(!F.canonical(uint256(1)<<128) && !F.canonical(uint256(1)<<255),"upper half");
        require(F.canonical(0),"zero");
    }
}
''')
if manifest.get('calldata_tail'):
    calldata_test=(root/'NativeCalldata.t.sol.in').read_text()
    if manifest.get('transpose_initial_fold'):
        calldata_test=calldata_test.replace('uint256[] memory weights=new uint256[](2*n);','uint256[] memory weights=new uint256[](1+4*((n+3)/4));weights[0]=n;')
        before='''weights[2*i]=uint256(uint32(w))|(uint256(uint32(w>>32))<<80)|(uint256(uint32(w>>64))<<160);
            weights[2*i+1]=w>>96;'''
        after='''for(uint256 lane;lane<4;++lane)weights[1+4*(i/4)+lane]|=uint256(uint32(w>>(32*lane)))<<(64*(3-i%4));'''
        assert calldata_test.count(before)==1
        calldata_test=calldata_test.replace(before,after,1)
        calldata_test=calldata_test.replace('uint256[] memory weights=new uint256[](2);','uint256[] memory weights=new uint256[](5);weights[0]=1;',1)
    (tests/'NativeCalldata.t.sol').write_text(calldata_test)
if manifest.get('assembly_closing'):
    (tests/'NativeMle.t.sol').write_text((root/'NativeMle.t.sol.in').read_text())
if manifest.get('native_closing_driver'):
    text=(root/'NativeClosingDriver.t.sol.in').read_text()
    assert text.count('DRIVER_HASH')==1
    (tests/'NativeClosingDriver.t.sol').write_text(text.replace('DRIVER_HASH',manifest['native_closing_module']['runtime_hash']))
if manifest.get('vector_proof_cache'):
    artifact=json.loads((a.build/'proof-cache-artifact.json').read_text())
    assert '0x'+kh(bytes.fromhex(artifact['runtime'])).hex()==manifest['proof_cache_module']['runtime_hash']
    (a.build/'proof-cache-creation.bin').write_bytes(bytes.fromhex(artifact['bytecode']))
    compiler.prepare_proof_cache()
    text=(root/'NativeVectorCache.t.sol.in').read_text()
    for before,after in [('CACHE_HASH',manifest['proof_cache_module']['runtime_hash']),
                         ('FIELD_COUNT',str(compiler.meta['field_count'])),
                         ('CACHE_BYTES',str(16*len(compiler.proof_cache_indices)+16)),
                         ('CACHE_RANGES',compiler.proof_cache_ranges.hex())]:
        text=text.replace(before,after)
    (tests/'NativeVectorCache.t.sol').write_text(text)
# Exercise the unchanged arithmetic, transcript and PCS regression tests against
# the native build's copies (whose diagnostic shape errors are compacted).
for original in (root.parent/'test').glob('*.sol'):
    if original.name=='NativeQuery.t.sol' and not manifest.get('offload_queries'):continue
    text=original.read_text()
    if original.name=='NativeQuery.t.sol' and manifest.get('offload_queries'):
        text=text.replace('{KoalaBear as F} from "../src/KoalaBear.sol"','{ReferenceKoalaBear as F} from "../src/ReferenceKoalaBear.sol"',1)
        text=text.replace('contract NativeQueryTest {','interface QueryVm {function envString(string calldata) external returns(string memory);function readFileBinary(string calldata) external view returns(bytes memory);}\ncontract NativeQueryTest {',1)
        before='    Q evaluator=new Q();'
        assert text.count(before)==1
        text=text.replace(before,'''    Q evaluator;
    constructor(){
        QueryVm vm=QueryVm(address(uint160(uint256(keccak256("hevm cheat code")))));
        bytes memory code=vm.readFileBinary(string.concat(vm.envString("NATIVE_BUILD"),"/closing-creation.bin"));
        address deployed;
        assembly("memory-safe"){deployed:=create(0,add(code,32),mload(code))}
        require(deployed!=address(0) && deployed.code.length<=24576,"selected query module deployment");
        evaluator=Q(deployed);
    }''',1)
        if manifest.get('canonical_query_inputs'):
            text=text.replace('evaluator.foldInitial(', 'initialCheckedBoth(').replace('evaluator.foldRows(', 'rowsCheckedBoth(')
            canonical_helpers='''
    function initialCheckedBoth(bytes memory fields,uint256[][] memory powers,uint256 point) private view returns(uint256[] memory actual){
        actual=evaluator.foldInitial(fields,powers,point);
        require(keccak256(abi.encode(actual))==keccak256(abi.encode(evaluator.foldInitialCanonical(fields,powers,point))),"canonical initial variant mismatch");
    }
    function rowsCheckedBoth(bytes memory fields,uint256[] memory point) private view returns(uint256[] memory actual){
        actual=evaluator.foldRows(fields,point);
        require(keccak256(abi.encode(actual))==keccak256(abi.encode(evaluator.foldRowsCanonical(fields,point))),"canonical row variant mismatch");
    }
    function testCanonicalQueryVariantsRetainShapeAndCoordinateGuards() public view {
        uint256[][] memory powers=new uint256[][](1);powers[0]=new uint256[](1);powers[0][0]=1;
        rejected(abi.encodeCall(evaluator.foldInitialCanonical,(new bytes(7),powers,1)));
        rejected(abi.encodeCall(evaluator.foldInitialCanonical,(new bytes(8),new uint256[][](0),1)));
        rejected(abi.encodeCall(evaluator.foldInitialCanonical,(new bytes(8),powers,F.P)));
        powers[0][0]=F.P;rejected(abi.encodeCall(evaluator.foldInitialCanonical,(new bytes(8),powers,1)));
        rejected(abi.encodeCall(evaluator.foldRowsCanonical,(new bytes(15),new uint256[](0))));
        rejected(abi.encodeCall(evaluator.foldRowsCanonical,(new bytes(0),new uint256[](25))));
        uint256[] memory point=new uint256[](1);point[0]=F.P;
        rejected(abi.encodeCall(evaluator.foldRowsCanonical,(new bytes(32),point)));
    }
'''
            if manifest.get('derived_query_inputs'):
                canonical_helpers=canonical_helpers.replace('testCanonicalQueryVariantsRetainShapeAndCoordinateGuards','testCanonicalShapesAndOriginalCoordinateGuards')
                # These three cases intentionally violate the Canonical API's
                # strengthened parameter precondition. The checked public API
                # continues to reject them; Canonical shape guards stay tested.
                for before,after in [
                    ('evaluator.foldInitialCanonical,(new bytes(8),powers,F.P)','evaluator.foldInitial,(new bytes(8),powers,F.P)'),
                    ('powers[0][0]=F.P;rejected(abi.encodeCall(evaluator.foldInitialCanonical,','powers[0][0]=F.P;rejected(abi.encodeCall(evaluator.foldInitial,'),
                    ('evaluator.foldRowsCanonical,(new bytes(32),point)','evaluator.foldRows,(new bytes(32),point)')]:
                    assert canonical_helpers.count(before)==1
                    canonical_helpers=canonical_helpers.replace(before,after,1)
            end=text.rfind('}');text=text[:end]+canonical_helpers+text[end:]
        if manifest.get('base_power_window'):
            power_helpers='''
    function powerLog(uint256 choice) private pure returns(uint256){
        uint256[5] memory logs=[uint256(17),19,21,23,24];return logs[choice%5];
    }
    function testFuzzDomainPowersMatchOriginal(bytes32 seed,uint8 rawLog,uint8 count) public view {
        uint256 log=powerLog(rawLog);uint256 n=uint256(count)%9;
        uint256[] memory indices=new uint256[](n);uint256[] memory expected=new uint256[](n);
        uint256 g=F.basePow(3,(F.P-1)>>log);
        for(uint256 i;i<n;++i){indices[i]=uint256(keccak256(abi.encode(seed,i)))% (1<<log);expected[i]=F.basePow(g,indices[i]);}
        require(keccak256(abi.encode(expected))==keccak256(abi.encode(evaluator.domainPowers(log,indices))),"domain window mismatch");
    }
    function testDomainPowersMaximumSingleBitsAndZero() public view {
        for(uint256 choice;choice<5;++choice){
            uint256 log=powerLog(choice);uint256[] memory indices=new uint256[](log+2);
            indices[1]=(1<<log)-1;for(uint256 bit;bit<log;++bit)indices[2+bit]=1<<bit;
            uint256[] memory expected=new uint256[](indices.length);uint256 g=F.basePow(3,(F.P-1)>>log);
            for(uint256 i;i<indices.length;++i)expected[i]=F.basePow(g,indices[i]);
            require(keccak256(abi.encode(expected))==keccak256(abi.encode(evaluator.domainPowers(log,indices))),"edge domain window mismatch");
        }
    }
    function testDomainPowersRejectBadDomainAndOutOfRangeIndex() public view {
        uint256[] memory indices=new uint256[](1);
        for(uint256 choice;choice<5;++choice){
            uint256 log=powerLog(choice);indices[0]=1<<log;
            rejected(abi.encodeCall(evaluator.domainPowers,(log,indices)));
            indices[0]=type(uint256).max;rejected(abi.encodeCall(evaluator.domainPowers,(log,indices)));
        }
        uint256[5] memory invalidLogs=[uint256(0),16,20,25,type(uint256).max];
        for(uint256 i;i<invalidLogs.length;++i)rejected(abi.encodeCall(evaluator.domainPowers,(invalidLogs[i],new uint256[](0))));
    }
'''
            end=text.rfind('}');text=text[:end]+power_helpers+text[end:]
    if original.name=='NativeClosing.t.sol' and manifest.get('closing_creation_hash'):
        text=text.replace('{KoalaBear as F} from "../src/KoalaBear.sol"','{ReferenceKoalaBear as F} from "../src/ReferenceKoalaBear.sol"',1)
        text=text.replace('contract NativeClosingTest {','interface ClosingVm {function envString(string calldata) external returns(string memory);function readFileBinary(string calldata) external view returns(bytes memory);}\ncontract NativeClosingTest {',1)
        before='    C evaluator=new C();'
        assert text.count(before)==1
        text=text.replace(before,'''    C evaluator;
    constructor(){
        ClosingVm vm=ClosingVm(address(uint160(uint256(keccak256("hevm cheat code")))));
        bytes memory code=vm.readFileBinary(string.concat(vm.envString("NATIVE_BUILD"),"/closing-creation.bin"));
        address deployed;
        assembly("memory-safe"){deployed:=create(0,add(code,32),mload(code))}
        require(deployed!=address(0) && deployed.code.length<=24576,"selected closing deployment");
        evaluator=C(deployed);
    }''',1)
        if manifest.get('calldata_closing'):
            prepared_helpers='''
    function testFuzzPreparedEndpointMatchesOriginal(bytes32 seed,uint8 size,uint8 rawLength,uint32 base) public view {
        uint256 n=uint256(size)%25;uint256 k=uint8(seed[0])%(n+1);
        uint256 count=uint256(rawLength)%33;count=count==0?1:2*count;
        uint256[] memory r=new uint256[](n);uint256[] memory poly=new uint256[](count);
        for(uint256 i;i<n;++i)r[i]=field(seed,i);
        for(uint256 i;i<count;++i)poly[i]=field(seed,100+i);
        uint256 x=uint256(base)%F.P;uint256 power=x;uint256 expectedFactor=1;
        for(uint256 i;i<k;++i){expectedFactor=F.mul(expectedFactor,F.add(F.sub(1,r[n-k+i]),F.scale(r[n-k+i],power)));power=mulmod(power,power,F.P);}
        (uint256 actualFactor,uint256 actualPolynomial)=evaluator.monomialPrepared(M.prepare(r,k),k,x,M.preparePolynomial(poly));
        require(actualFactor==expectedFactor && actualPolynomial==F.hornerBase(poly,power),"prepared endpoint mismatch");
    }
    function testPreparedEndpointEdgesAndShapeRejections() public view {
        uint256[] memory r=new uint256[](24);uint256 maximum=(F.P-1)*0x1000000010000000100000001;
        for(uint256 i;i<r.length;++i)r[i]=maximum;
        uint256[5] memory dims=[uint256(0),1,2,15,24];uint256[4] memory lengths=[uint256(1),2,6,32];
        for(uint256 d;d<dims.length;++d)for(uint256 l;l<lengths.length;++l){
            uint256[] memory poly=new uint256[](lengths[l]);for(uint256 i;i<poly.length;++i)poly[i]=maximum;
            uint256[] memory cache=M.prepare(r,dims[d]);uint256[] memory wide=M.preparePolynomial(poly);
            for(uint256 edge;edge<3;++edge){
                uint256 x=edge==2?F.P-1:edge;uint256 power=x;uint256 expected=1;
                for(uint256 i;i<dims[d];++i){expected=F.mul(expected,F.add(F.sub(1,maximum),F.scale(maximum,power)));power=mulmod(power,power,F.P);}
                (uint256 factor,uint256 value)=evaluator.monomialPrepared(cache,dims[d],x,wide);
                require(factor==expected && value==F.hornerBase(poly,power),"prepared endpoint edge mismatch");
            }
        }
        uint256[] memory empty=new uint256[](0);uint256[] memory cache=new uint256[](1);uint256[] memory wide=new uint256[](2);
        bytes[4] memory bad=[abi.encodeCall(evaluator.monomialPrepared,(cache,0,F.P,wide)),abi.encodeCall(evaluator.monomialPrepared,(cache,2,1,wide)),abi.encodeCall(evaluator.monomialPrepared,(cache,0,1,empty)),abi.encodeCall(evaluator.monomialPrepared,(cache,0,1,new uint256[](3)))];
        for(uint256 i;i<bad.length;++i){(bool ok,bytes memory error)=address(evaluator).staticcall(bad[i]);require(!ok && error.length>0,"malformed prepared input accepted or OOG");}
    }
'''
            end=text.rfind('}');text=text[:end]+prepared_helpers+text[end:]
    if manifest.get('fused_base') and original.name=='StackedWhir.t.sol':
        text=text.replace('{StackedWhir as W} from "../src/StackedWhir.sol"','{ReferenceStackedWhir as W} from "../src/ReferenceStackedWhir.sol"')
        if manifest.get('fast_whir_transcript'):text=text.replace('{KeccakTranscript as T} from "../src/KeccakTranscript.sol"','{ReferenceKeccakTranscript as T} from "../src/ReferenceKeccakTranscript.sol"')
    (tests/original.name).write_text(text)
subprocess.run([sys.executable,str(root.parent/'test-compiler.py'),str(a.fixtures.resolve())],check=True)
env=os.environ.copy();env['NATIVE_BUILD']=str(a.build.resolve());env['WIRE_FIXTURE']=str(a.fixtures.resolve())
raise SystemExit(subprocess.call(['forge','test','--root',str(a.build.resolve()),'-vv',*extra],env=env))
