#!/usr/bin/env python3
"""Build-time trust-boundary checks against an approved external fixture."""
import copy
import importlib.util
import json
import re
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('native_compiler',HERE/'compile.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
from wire import parse, entry_source, split_sources, register_result_runs, dense_driver_source
from transport import encode, decode, encode_zero_runs


class NativeCompilerTests(unittest.TestCase):
    def test_shared_power_table_preserves_all_approved_generator_values(self):
        source=(HERE.parent/'src/NativeQueryEvaluator.sol').read_text()
        for bits in (4,6):
            tables=m.domain_power_tables(self.compiler,bits);maximum=max(tables)
            shared=m.windowed_query_powers(source,self.compiler,bits,True)
            self.assertEqual(shared.count('table=hex"'),1)
            self.assertIn('index:=shl(sub('+str(maximum)+',log),index)',shared)
            for log in tables:
                g=pow(3,(m.P-1)>>log,m.P)
                for i in [0,1,(1<<log)-1,*[1<<j for j in range(log)]]:
                    shifted=i<<(maximum-log);value=1
                    for k in range((maximum+bits-1)//bits):
                        at=4*((k<<bits)+((shifted>>(bits*k))&((1<<bits)-1)))
                        value=value*int.from_bytes(tables[maximum][at:at+4],'big')%m.P
                    self.assertEqual(value,pow(g,i,m.P))

    def test_zero_run_transport_round_trip_and_command_bounds(self):
        import random
        rng=random.Random(38138)
        for fields in (0,1,7,8,9,31,64,32768):
            for minimum in (1,4,8,16):
                values=[bytes(4) if i%29<23 else rng.randbytes(4) for i in range(fields)]
                raw=b'ZKET\x01\x00'+rng.randbytes(32)+b''.join(values)+b'\xff'*32+b'\xff'*32
                packed=encode_zero_runs(raw,fields,2,minimum)
                self.assertEqual(decode(packed,fields,2),raw)
                for bad in (packed[:-1],packed+b'\0'):
                    with self.assertRaises(ValueError):decode(bad,fields,2)
        raw=b'ZKET\x01\x00'+bytes(32)+bytes(4*8)
        good=encode_zero_runs(raw,8,0)
        for cmd in (0,9,0x8000,0x8008):
            with self.assertRaises(ValueError):decode(good[:38]+cmd.to_bytes(2,'big'),8,0)
        for value in (bytes(4),b'\xff'*4):
            raw=b'ZKET\x01\x00'+bytes(32)+value*65536
            self.assertEqual(decode(encode_zero_runs(raw,65536,0),65536,0),raw)

    def test_zero_run_entry_checks_expanded_fields_before_cache(self):
        c=copy.copy(self.compiler);c.zero_run_fields=True;c.prepare_proof_cache();c.closing_module_hash='0x'+'11'*32
        _,entry=split_sources(entry_source(c,'00'*32,128))
        self.assertIn('wire[5]!=0x03',entry)
        self.assertIn('Wire.validateMemoryFields(context,',entry)
        cache={'runtime':'6000','bytecode':'6001'}
        c.inplace_tail=True
        updated=m.offload_cache_entry(entry,c,cache)
        self.assertLess(updated.index('Wire.validateMemoryFields'),updated.index('staticcall(gas(),cacheTarget'))
        self.assertIn('if iszero(eq(byte(5,calldataload(wire.offset)),3))',updated)

    def test_identity_branch_intervals_select_complete_kernels_only(self):
        c=copy.copy(self.compiler);c.ops=[[6,0,1,2],[6,3,0,2]];c.pcs=[0,1]
        c.tower_mulmod=True;c.branchless_products=True
        baseline=c.kernel(0,2,'IdentityPolicy')
        c.identity_branch_spans=[[1,2]]
        self.assertEqual(c.kernel(0,2,'IdentityPolicy'),baseline)
        c.identity_branch_spans=[[0,2]]
        selected=c.kernel(0,2,'IdentityPolicy')
        self.assertIn('if or(lt(packedLeft,2),lt(packedRight,2))',selected)
        self.assertNotIn('if or(lt(packedLeft,2),lt(packedRight,2))',baseline)
        c.lazy_linear_products=True
        with self.assertRaisesRegex(AssertionError,'complete tower formula'):
            c.kernel(0,2,'InvalidIdentityDeferral')

    def test_native_closing_reuses_original_cores_and_pins_child(self):
        original=m.monomial_yul_core(m.isolate_monomial_closing((HERE.parent/'src/NativeClosingEvaluator.sol').read_text()),4)
        generated=m.native_closing_source(original)
        mono=m.block(original,'function monomialPrepared(')
        self.assertEqual(m.block(generated,'function factorCore('),m.block(mono,'function factorCore(').replace('calldataload(','mload('))
        horner=m.block(mono,'function hornerCore(').replace('calldataload(','mload(')
        self.assertEqual(m.block(generated,'function hornerCore('),m.unroll_closing_horner(horner))
        wrapper=m.native_closing_wrapper(original,{'runtime':'6000','bytecode':'6001'})
        self.assertEqual(wrapper.count('0x'+m.kh(bytes.fromhex('6000')).hex()),2)
        self.assertIn('target.codehash==',m.block(wrapper,'function evaluate('))
        self.assertIn('iszero(eq(returndatasize(),32))',wrapper)
        self.assertNotIn('immutable',wrapper)

    def test_vector_cache_retains_exact_scalar_and_odd_tails(self):
        c=copy.copy(self.compiler);c.prepare_proof_cache()
        source=m.proof_cache_module_source(c);vector=m.vectorize_proof_cache(source)
        self.assertIn('pop(memoryguard(',vector)
        self.assertIn('and(count,not(15))',vector)
        self.assertIn('dst:=add(dst,256) src:=add(src,256)',vector)
        for marker in ('for {} lt(dst,pairEnd)','if and(count,1)'):
            self.assertEqual(m.block(source,marker),m.block(vector,marker))
        self.assertEqual(m.block(source,'function reversePair('),m.block(vector,'function reversePair('))
        self.assertIn('return(0,'+str(16*len(c.proof_cache_indices)+16)+')',vector)

    def test_dense_result_layout_rejects_outside_register_region(self):
        for registers in ([-1],[5],[1,1],[2,1],[False]):
            with self.assertRaises(AssertionError):register_result_runs(registers,5)
        for count in (0,-1,False):
            with self.assertRaises(AssertionError):register_result_runs([],count)

    def test_dense_result_layout_covers_each_full_word_once(self):
        import random
        rng=random.Random(48310)
        for count in (1,5,64,1047):
            for _ in range(16):
                writes=sorted(rng.sample(range(count),rng.randrange(count+1)))
                runs=register_result_runs(writes,count)
                expanded=[]
                for dst,src,size in runs:
                    self.assertEqual(src,288+32*len(expanded))
                    expanded.extend(range(dst//32,(dst+size)//32))
                self.assertEqual(expanded,writes)
        self.assertEqual(register_result_runs([],5),[])

    def test_dense_driver_requires_matching_approved_kernel_count(self):
        with self.assertRaises(AssertionError):dense_driver_source([],5)
        c=copy.copy(self.compiler)
        c.contiguous_results=True
        with self.assertRaisesRegex(AssertionError,'result layouts'):
            entry_source(c,'00'*32,0)

    def test_packed_poseidon_rejects_noncanonical_diagonal(self):
        data=next(op[-1] for op in self.manifest['ops'] if op[0]==18)
        source=(HERE.parent/'src/KoalaBearPoseidon2.sol').read_text()
        diagonal=re.search(r'hex"([0-9a-f]+)"',source)[1]
        invalid=source.replace(diagonal,m.P.to_bytes(4,'big').hex()+diagonal[8:],1)
        with patch.object(Path,'read_text',return_value=invalid):
            with self.assertRaisesRegex(AssertionError,'Poseidon diagonal'):
                m.specialized_poseidon(data,True,True)

    def test_packed_poseidon_circulant_layer_and_unreduced_bounds(self):
        import random
        radix=1<<64;modulus=(1<<256)-1
        constant=2+radix+radix**2+3*radix**3
        self.assertIn(hex(constant),m.packed_poseidon_linear())
        rng=random.Random(44391)
        vectors=[[0]*16,[m.P-1]*16,*[[int(i==j)*(m.P-1) for i in range(16)] for j in range(16)]]
        vectors += [[rng.randrange(m.P) for _ in range(16)] for _ in range(256)]
        for values in vectors:
            blocks=[]
            for g in range(4):
                a,b,c,d=values[4*g:4*g+4];total=a+b+c+d
                blocks.append([total+a+2*b,total+b+2*c,total+c+2*d,total+d+2*a])
            expected=[blocks[g][j]+sum(row[j] for row in blocks) for g in range(4) for j in range(4)]
            packed=[sum(values[4*g+j]<<(64*j) for j in range(4))*constant%modulus for g in range(4)]
            summed=sum(packed)
            actual=[((row+summed)>>(64*j))&((1<<64)-1) for row in packed for j in range(4)]
            self.assertEqual(actual,expected)
            self.assertLess(max(actual),35*m.P)
        self.assertLess((36*m.P)**3,1<<111)
        self.assertLess(35*m.P*(m.P-1)+560*m.P,1<<68)

    def test_transposed_initial_preserves_all_other_math_functions(self):
        source=(HERE.parent/'src/NativeWhirMath.sol').read_text()
        result=m.transposed_initial_math(source)
        for name in ('firstWeights','firstDot'):
            old=m.block(source,'function '+name+'(');new=m.block(result,'function '+name+'(')
            source=source.replace(old,'<'+name+'>',1);result=result.replace(new,'<'+name+'>',1)
        self.assertEqual(result,source)
        self.assertLess(4*(m.P-1)**2,1<<64)
        self.assertLess(65536*(m.P-1)**2,1<<78)

    def test_matrix_operand_permutation_has_disjoint_product_slots(self):
        mask=(1<<32)-1
        constant=(1<<192)+(1<<96)+1
        selected=(mask<<64)|(mask<<128)|(mask<<192)
        # Coefficient i occupies i+3*j after the three-tap multiplication.
        # All surviving slots are distinct; there is no integer lane carry.
        slots=[i+3*j for i in range(3) for j in range(3) if i+3*j<8]
        self.assertEqual(sorted(slots),list(range(8)))
        samples=[0,(1<<128)-1,*[1<<i for i in range(128)]]
        samples += [((m.P-1)*0x1000000010000000100000001),0x80000000800000008000000080000000]
        for a in samples:
            actual=(a>>96)|((((a&((1<<96)-1))*constant)&((1<<256)-1))&selected)
            expected=sum(((a>>(32*i))&mask)<<(64*(3-i)) for i in range(4))
            self.assertEqual(actual,expected)

    def test_tensor_query_preserves_public_input_guards(self):
        source=(HERE.parent/'src/NativeQueryEvaluator.sol').read_text()
        stream=m.stream_query_evaluator(m.matrix_query_evaluator(source))
        tensor=m.tensor_query_evaluator(stream)
        old=m.block(stream,'function foldRows(')
        expected=old.replace('uint256[] memory matrices=prepareCoordinates(point);uint256[] memory row=new uint256[](width>>1);','uint256[] memory basis=prepareBasis(point);').replace('foldStream(fields,q*stride,width,matrices,row)','foldBasis(fields,q*stride,width,basis)')
        self.assertEqual(m.block(tensor,'function foldRows('),expected)
        self.assertEqual(m.block(tensor,'function foldInitial('),m.block(source,'function foldInitial('))
        self.assertNotIn('function foldStream(',tensor)
        self.assertLess(4*(m.P-1)**2,1<<64)
        self.assertLess((1<<24)*4*(m.P-1)**2,1<<88)

    def test_tensor_direct_decoder_all_wire_bits_and_halfword_isolation(self):
        # Mathematical LE32 coefficient order, independent of decoder stages.
        mask=(1<<32)-1
        def direct(w):
            even_bytes=int('00ff'*16,16);even_pairs=int('0000ffff'*8,16)
            w=((w&even_bytes)<<8)|((w>>8)&even_bytes)
            w=((w&even_pairs)<<16)|((w>>16)&even_pairs)
            value=w>>128
            value=((value&(((1<<64)-1)<<64))<<64)|(value&((1<<64)-1))
            return ((value&((mask<<160)|(mask<<32)))<<32)|(value&((mask<<128)|mask))
        for w in [0,(1<<256)-1,*[1<<bit for bit in range(256)]]:
            raw=w.to_bytes(32,'big')
            coefficients=[int.from_bytes(raw[4*i:4*i+4],'little') for i in range(4)]
            expected=sum(value<<(64*(3-i)) for i,value in enumerate(coefficients))
            self.assertEqual(direct(w),expected)

    def test_four_step_calldata_horner_changes_only_bounded_polynomial_core(self):
        source=m.isolate_monomial_closing((HERE.parent/'src/NativeClosingEvaluator.sol').read_text())
        two=m.monomial_yul_core(source,2);four=m.monomial_yul_core(source,4)
        self.assertEqual(m.block(two,'function factorCore('),m.block(four,'function factorCore('))
        self.assertEqual(two.replace(m.block(two,'function hornerCore('),'<horner>'),four.replace(m.block(four,'function hornerCore('),'<horner>'))
        self.assertLess(4*(m.P-1)**2+(m.P-1),1<<64)
        body=m.block(four,'function hornerCore(')
        self.assertIn('if mod(coefficientCount,4)',body)
        self.assertIn('at:=sub(at,64)',body)
        self.assertIn('at:=sub(at,128)',body)
        self.assertIn('case 1 {acc:=calldataload(start)}',body)
        self.assertEqual(body.count('acc:=or(or(mod(and(product,mask),p)'),2)

    def test_isolated_monomial_keeps_original_arithmetic_and_owned_request_shape(self):
        source=(HERE.parent/'src/NativeClosingEvaluator.sol').read_text()
        transformed=m.isolate_monomial_closing(source)
        math=(HERE.parent/'src/NativeClosingMath.sol').read_text()
        original=m.block(m.assembly_closing_math(math),'function evaluate(')
        expected=original.replace('function evaluate(','function factorCalldata(',1).replace('uint256[] memory cache','uint256[] calldata cache',1).replace('internal pure','private pure',1)
        expected=expected.replace('let start:=add(cache,32)','let start:=cache.offset',1).replace('mload(','calldataload(')
        self.assertEqual(expected,m.block(transformed,'function factorCalldata('))
        original=m.block(math,'function hornerPrepared(')
        expected=original.replace('function hornerPrepared(','function hornerCalldata(',1).replace('uint256[] memory wide','uint256[] calldata wide',1).replace('internal pure','private pure',1)
        expected=expected.replace('let start:=add(wide,32)','let start:=wide.offset',1).replace('mload(wide)','wide.length').replace('mload(','calldataload(')
        self.assertEqual(expected,m.block(transformed,'function hornerCalldata('))
        for statement in ('request=new bytes(196+32*(cache.length+wide.length))','mstore(add(at,4),128)','mstore(add(at,100),add(160,cacheBytes))','mcopy(add(at,164),add(cache,32),cacheBytes)','mcopy(add(add(at,196),cacheBytes),add(wide,32),mul(mload(wide),32))','mstore(add(at,68),x)','staticcall(gas(),address(),at,mload(request),result,64)','eq(returndatasize(),64)','total=F.add(total,F.mul(coeff,F.mul(factor,evaluation)))'):
            self.assertIn(statement,transformed)
        self.assertIn('if(x>=F.P)revert InvalidClosingInput();',transformed)
        self.assertIn('if(!F.canonical(value))revert InvalidClosingInput();',transformed)

    def test_window_tables_match_original_generators_and_own_read_guard(self):
        for bits in (4,6):
            tables=m.domain_power_tables(self.compiler,bits)
            self.assertEqual(sorted(tables),[17,19,21,23,24])
            for log,table in tables.items():
                self.assertEqual(table[-32:],bytes(32))
                generator=pow(3,(m.P-1)>>log,m.P);cursor=0
                for k in range((log+bits-1)//bits):
                    for digit in range(1<<min(bits,log-k*bits)):
                        actual=int.from_bytes(table[cursor:cursor+4],'big');cursor+=4
                        self.assertEqual(actual,pow(generator,digit*(1<<(k*bits)),m.P))
                self.assertEqual(cursor,len(table)-32)
                self.assertLessEqual(cursor-4+32,len(table))

    def test_windowed_points_retain_transcript_and_proof_checks(self):
        cfg=parse(self.compiler.tail)[0]
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        source=m.native_whir_library(m.recycle_whir_scratch(source))
        source=m.specialize_whir_generators(m.native_merkle_path_views(source),cfg)
        source=m.closing_module_whir(m.fused_base_whir(source,cfg))
        source=m.canonical_query_whir(m.validated_leaf_fields(m.offload_query_whir(m.calldata_whir(source,self.compiler.wire_bytes))))
        source=m.fixed_whir_profile(source,self.compiler)
        transformed=m.windowed_whir_points(source)
        # Exponentiation is pure. Draws and authentication keep their order;
        # no random value, leaf/root check or claim equation is removed.
        for pattern in (r't\.\w+\([^;]+;',r'checkMerkle\([^;]+;',r'checkContinuation\([^;]+;',r'if \(.*?\) revert InvalidWhir\(\d\);'):
            self.assertEqual(re.findall(pattern,source),re.findall(pattern,transformed))
        self.assertIn('stirPoints[q][0] = bases[q];',transformed)
        self.assertIn('finalIndices[q]=index;',transformed)
        self.assertIn('F.hornerBase(p.finalPoly,finalBases[q])',transformed)
        self.assertIn('domainPowers(w.domainLog,finalIndices)',transformed)

    def test_merkle_unrolling_reads_every_full_word_with_scalar_tail(self):
        source=(HERE.parent/'src/NativeMerklePath.sol').read_text()
        for factor in (4,8):
            transformed=m.unroll_merkle_paths(source,factor)
            for name,load in (('walk','mload'),('walkCalldata','calldataload')):
                body=m.block(transformed,'function '+name+'(')
                self.assertEqual(body.count(load+'('),factor+1)
                self.assertEqual(body.count('hash:=keccak256(0,64)'),factor+1)
                self.assertEqual(body.count('index:=shr(1,index)'),factor+1)
                self.assertIn(f'mod(height,{factor})',body)
                self.assertIn('for {} lt(pathPointer,end) {pathPointer:=add(pathPointer,32)}',body)
                self.assertIn('mstore(side,hash) mstore(xor(side,32),sibling)',body)
        # Do not silently discard a future source guard during replacement.
        altered=source.replace('return hash;','require(height<25,"height");return hash;',1)
        with self.assertRaises(AssertionError):m.unroll_merkle_paths(altered,8)

    def test_fixed_whir_geometry_rejects_every_malformed_dimension(self):
        from wire import parse
        original=parse(self.compiler.tail)
        self.assertEqual(m.check_fixed_whir_geometry(*original),5)
        changes=[lambda c,r,s,p,w:c.update(n=25),
                 lambda c,r,s,p,w:c['rounds'][0]['foldPow'].pop(),
                 lambda c,r,s,p,w:p.pop(),
                 lambda c,r,s,p,w:w['finalPoly'].pop(),
                 lambda c,r,s,p,w:w['finalPolys'][0].pop(),
                 lambda c,r,s,p,w:w['roots'].pop(),
                 lambda c,r,s,p,w:w['batch'][0].pop(),
                 lambda c,r,s,p,w:w['roundPolys'][0][0].pop(),
                 lambda c,r,s,p,w:w['roundOod'][0].pop(),
                 lambda c,r,s,p,w:w['foldPow'].pop(),
                 lambda c,r,s,p,w:w['openings'][0].pop(),
                 lambda c,r,s,p,w:w['openings'][1][0]['values'][0].pop(),
                 lambda c,r,s,p,w:w['openings'][1][0]['path'].pop(),
                 lambda c,r,s,p,w:w['openings'][1][0]['path'].__setitem__(0,0x40000001),
                 lambda c,r,s,p,w:w['openings'][0][0]['values'][0].__setitem__(0,0x10000000)]
        for change in changes:
            altered=copy.deepcopy(original);change(*altered)
            with self.assertRaises(AssertionError):m.check_fixed_whir_geometry(*altered)

    def test_fixed_whir_profile_retains_full_protocol_and_merkle_equations(self):
        cfg=parse(self.compiler.tail)[0]
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        source=m.native_whir_library(m.recycle_whir_scratch(source))
        source=m.specialize_whir_generators(m.native_merkle_path_views(source),cfg)
        source=m.closing_module_whir(m.fused_base_whir(source,cfg))
        source=m.canonical_query_whir(m.validated_leaf_fields(m.offload_query_whir(m.calldata_whir(source,self.compiler.wire_bytes))))
        transformed=m.fixed_whir_profile(source,self.compiler)
        self.assertEqual(m.block(source,'function verify('),m.block(transformed,'function verify('))
        for name in ('validate','checkMerkle'):
            source=source.replace(m.block(source,'function '+name+'('),'<'+name+'>')
            transformed=transformed.replace(m.block(transformed,'function '+name+'('),'<'+name+'>')
        self.assertEqual(source,transformed)

    def test_selective_stack_registers_preserve_unselected_kernel_source(self):
        c=copy.copy(self.compiler);c.ops=[[6,2,0,1],[4,3,2,1],[8,0,3,3]];c.pcs=[0,1,2]
        c.stack_registers=False;original=c.kernel(0,3,'Small')
        c.stack_registers=True;c.stack_register_spans=[[1,3]]
        self.assertEqual(c.kernel(0,3,'Small'),original)
        c.stack_register_spans=[[0,3]]
        self.assertIn('stackReg_',c.kernel(0,3,'Small'))

    def test_stack_register_code_preserves_dynamic_operands_and_other_memory(self):
        code=['mstore(0x40,memoryguard(4096))',
              'mstore(256,calldataload(0)) mstore(288,calldataload(32))',
              'mstore(320,times(mload(256),mload(288)))',
              'for {let j:=0} lt(j,2) {j:=add(j,1)} {mstore(320,plus(mload(320),mload(add(288,mul(j,32)))))}',
              'mstore(4096,mload(320)) mcopy(0,352,288) return(4096,32)']
        transformed=m.stack_register_code(code,{7:0,8:1,9:2},{8,9})
        self.assertEqual(transformed[0],code[0])
        self.assertEqual(transformed[1],'let stackReg_0:=0')
        self.assertEqual(transformed[2],'stackReg_0:=calldataload(0) mstore(288,calldataload(32))')
        self.assertEqual(transformed[3],'mstore(320,times(stackReg_0,mload(288)))')
        self.assertEqual(transformed[4:],code[3:])
        self.assertEqual(m.stack_register_code(code,{7:0,8:1,9:2},{7,8,9}),code)

    def test_tracked_partial_sum_keeps_external_rounds_and_diagonal(self):
        data=next(op[-1] for op in self.manifest['ops'] if op[0]==18)
        original=m.specialized_poseidon(data,True);tracked=m.specialized_poseidon(data,True,True)
        self.assertEqual(m.block(original,'function linear('),m.block(tracked,'function linear('))
        before=original.index('for{let step:=0}');after=tracked.index('let partialSum:=')
        self.assertEqual(original[:before],tracked[:after])
        # The original eight external rounds surround the same twenty keyed
        # partial steps; only integer state-sum bookkeeping changes.
        key=int.from_bytes(bytes.fromhex(data)[24*64:24*64+4],'big')
        suffix=f'{{let x:=add(mload(add(state,0)),{key})'
        self.assertEqual(original[original.index(suffix):],tracked[tracked.index(suffix):])
        self.assertEqual(tracked.count('nextSum:=add(nextSum,value)'),16)
        self.assertIn('partialSum:=add(sub(partialSum,oldFirst),nextFirst)',tracked)
        self.assertIn('partialSum:=nextSum',tracked)
        self.assertIn('for{let step:=0}lt(step,20)',tracked)
        original_diagonal=re.findall(r'mul\(mload\(add\(state,\d+\)\),(\d+)\)',original)
        tracked_diagonal=re.findall(r'mul\(mload\(add\(state,\d+\)\),(\d+)\)',tracked)
        self.assertEqual(original_diagonal,tracked_diagonal)

    def test_canonical_query_variants_keep_checked_methods_and_every_other_guard(self):
        source=(HERE.parent/'src/NativeQueryEvaluator.sol').read_text()
        source=m.assembly_initial_query_evaluator(m.stream_query_evaluator(m.matrix_query_evaluator(source)))
        transformed=m.canonical_query_evaluator(source)
        for name in ('foldInitial','foldRows'):
            original=m.block(source,'function '+name+'(')
            self.assertEqual(original,m.block(transformed,'function '+name+'('))
            variant=m.block(transformed,'function '+name+'Canonical(')
            expected=original.replace('function '+name+'(','function '+name+'Canonical(',1).replace('Wire.validateFields(fields,0,fields.length/4);',"// Requires the complete entry's global validation of these exact field bytes.",1)
            self.assertEqual(expected,variant)
        interface=m.canonical_query_interface((HERE.parent/'src/INativeQueryEvaluator.sol').read_text())
        for name in ('foldInitial','foldRows'):
            self.assertIn('function '+name+'Canonical(',interface)

    def test_validated_leaf_fields_remove_only_redundant_scan(self):
        cfg=parse(self.compiler.tail)[0]
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        source=m.native_whir_library(m.recycle_whir_scratch(source))
        source=m.specialize_whir_generators(m.native_merkle_path_views(source),cfg)
        source=m.closing_module_whir(m.fused_base_whir(source,cfg))
        source=m.offload_query_whir(m.calldata_whir(source,self.compiler.wire_bytes))
        transformed=m.validated_leaf_fields(source)
        before='checkMemory(start,div(byteCount,4),invalidField)'
        self.assertEqual(source.replace(before,'<entry validated fields>'),transformed.replace('// Fields were validated by the complete entry before any kernel call.','<entry validated fields>'))
        c=copy.copy(self.compiler);c.offload_queries=True;c.calldata_tail=True
        c.closing_module_hash='0x'+'11'*32
        tail,entry=split_sources(entry_source(c,'00'*32,128,path_views=True,fused_base=True))
        self.assertLess(entry.index('Wire.validateFields(wire,38,'),entry.index('context=new bytes('))
        self.assertIn(f'Wire.validateFields(wire,38,{c.meta["field_count"]})',entry)
        # Decoder generation has independently checked each leaf's tag,
        # contiguity and operand bounds before constructing packet views.
        self.assertIn('p.dataViews[0]=packetOffset+',tail)
        self.assertNotIn('leaf.source=msg.',tail)

    def test_assembly_closing_keeps_shape_guards_and_paired_formula(self):
        source=(HERE.parent/'src/NativeClosingMath.sol').read_text()
        transformed=m.assembly_closing_math(source)
        before=m.block(source,'function evaluate(');after=m.block(transformed,'function evaluate(')
        self.assertEqual(source.replace(before,'<paired evaluator>'),transformed.replace(after,'<paired evaluator>'))
        self.assertIn('require(x<F.P && cache.length==4*(k/2)+1,"closing cache");',after)
        original=m.block(before,'assembly("memory-safe")')
        body=original[original.index('{')+1:-1].replace('let at:=add(add(cache,32),mul(i,128))','').replace('pair:=','let pair:=',1)
        self.assertIn(body,after)
        self.assertIn('mload(end),addmod(x,0x7f000000,0x7f000001)',after)

    def test_assembly_mle_preserves_copy_shape_and_zero_width_rejection(self):
        source=(HERE.parent/'src/KoalaBear.sol').read_text()
        transformed=m.assembly_mle_library(source)
        before=m.block(source,'function mle(');after=m.block(transformed,'function mle(')
        self.assertEqual(source.replace(before,'<MLE>'),transformed.replace(after,'<MLE>'))
        self.assertIn('require(values.length == 1 << point.length, "MLE shape");',after)
        self.assertIn('mcopy(data,add(values,32),mul(n,32))',after)
        self.assertIn('folded=row[0];',after)
        self.assertIn('mstore(dst,plus(a,times(x,minus(mload(add(src,32)),a))))',after)

    def test_assembly_initial_retains_public_guards_and_original_dot(self):
        source=(HERE.parent/'src/NativeQueryEvaluator.sol').read_text()
        transformed=m.assembly_initial_query_evaluator(source)
        before=m.block(source,'for(uint256 q;q<values.length;++q){')
        after=m.block(transformed,'assembly("memory-safe")')
        self.assertEqual(source.replace(before,'<query loop>'),transformed.replace(after,'<query loop>'))
        dot=m.block((HERE.parent/'src/NativeWhirMath.sol').read_text(),'function firstDot(')
        body=m.block(dot,'assembly("memory-safe")')
        self.assertIn(re.sub(r'\bweights\b','dotWeights',body[body.index('{')+1:-1]),after)
        for guard in ('mod(mload(weights),2)','gt(n,65534)','gt(offset,mload(source))','gt(n,div(sub(mload(source),offset),4))'):
            self.assertIn(guard.replace('weights','dotWeights'),after)
        self.assertIn('0x'+m.kh(b'InvalidNativeWhirMath()')[:4].hex(),after)
        # Four prepared words per lambda, eight bytes per adjacent base pair.
        self.assertIn('offset:=add(offset,mul(mload(rootWeights),2))',after)

    @classmethod
    def setUpClass(cls):
        cls.manifest=json.loads((FIXTURE/'compiled/program.json').read_text())
        cls.program=(FIXTURE/'compiled/program.bin').read_bytes()
        cls.compiler=m.Compiler(cls.manifest,cls.program)

    def test_approved_operand_cannot_be_replaced(self):
        altered=copy.deepcopy(self.manifest)
        op=next(x for x in altered['ops'] if x[0] in (4,5,6))
        op[-1]=0x80000007
        with self.assertRaises(AssertionError):m.Compiler(altered,self.program)

    def test_complete_tail_and_exact_consumption(self):
        cfg,roots,stripes,point,proof=parse(self.compiler.tail)
        self.assertEqual(cfg['n'],len(point))
        self.assertEqual(len(roots),len(stripes))
        self.assertEqual(stripes,self.manifest['stripes'])
        self.assertEqual(len(proof['openings']),len(cfg['rounds']))
        for bad in [self.compiler.tail[:-1],self.compiler.tail+b'\0']:
            with self.assertRaises(AssertionError):parse(bad)

    def test_hash_transport_reconstructs_every_original_byte(self):
        c=self.compiler
        raw=(FIXTURE/'raw.bin').read_bytes()
        packed=encode(raw,c.meta['field_count'],c.meta['hash_count'])
        self.assertEqual(decode(packed,c.meta['field_count'],c.meta['hash_count']),raw)
        self.assertLess(len(packed),len(raw))
        prefix=38+4*c.meta['field_count']
        first=int.from_bytes(packed[prefix:prefix+2],'big')&0x7fff
        at=prefix+2+32*first
        bad=packed[:at]+first.to_bytes(2,'big')+packed[at+2:]
        for value in (packed[:-1],packed+b'\0',bad,packed[:prefix]+b'\x80\x00'+packed[prefix+2:]):
            with self.assertRaises(ValueError):decode(value,c.meta['field_count'],c.meta['hash_count'])

    def test_hash_transport_literals_references_and_all_digest_bits(self):
        import random
        rng=random.Random(281833)
        for count in (0,1,2,7,8,31,64,257):
            pool=[rng.randbytes(32) for _ in range(7)]
            for repeated in (False,True):
                values=[pool[i%7] if repeated else rng.randbytes(32) for i in range(count)]
                raw=b'ZKET\x01\x00'+rng.randbytes(32)+b'\xff'*12+b''.join(values)
                self.assertEqual(decode(encode(raw,3,count),3,count),raw)

    def test_tail_metadata_does_not_depend_on_entry_pin(self):
        tail,entry=split_sources(entry_source(self.compiler,'00'*32,128))
        self.assertNotIn('CompiledTerminalVerifier',tail)
        self.assertNotIn('HashDictionaryWire',tail)
        self.assertIn('import {CompiledWhirVerifier}',entry)
        self.assertEqual(entry.count('keccak256(type(CompiledWhirVerifier).runtimeCode)'),1)
        self.assertIn('Wire.validateFields(wire,38,',entry)
        self.assertIn('Dictionary.decodeInto(wire,context,',entry)

    def test_native_workspace_is_disjoint(self):
        altered=copy.deepcopy(self.manifest);altered['registers']=1263
        with self.assertRaisesRegex(AssertionError,'workspace overlaps'):
            m.Compiler(altered,self.program)

    def test_static_proof_and_constant_bounds(self):
        c=self.compiler;nf=c.meta['field_count'];nh=c.meta['hash_count']
        for bad in [0x40000000+nf,0x20000000+nf-3,0x10000000+nh,0x80000000+m.P]:
            with self.assertRaises(AssertionError):c.ref(bad)
        c.ref(0x40000000+nf-1);c.ref(0x20000000+nf-4);c.ref(0x10000000+nh-1)

    def test_sparse_access_reads_before_aliased_writes(self):
        c=copy.copy(self.compiler)
        c.ops=[[4,2,2,3], [6,3,2,4], [8,0,3,5], [17,0,5,7],
               [14,0,20,6], [15,7,25], [18,8,0,16,'00'], [16,16,0x10000000]]
        inputs,written,used=c.register_access(0,len(c.ops))
        self.assertEqual(inputs,[2,3,4,5,6])
        self.assertEqual(written,[2,3]+list(range(7,24)))
        self.assertEqual(used,list(range(2,24)))

    def test_sparse_codegen_preserves_original_packet_offsets(self):
        c=self.compiler
        start=next(i for i,op in enumerate(c.ops) if op[0]==16)
        source=c.kernel(start,start+1,'SparseTest')
        inputs,written,used=c.register_access(start,start+1)
        self.assertIn(f'calldatasize(),{c.packet+c.wire_bytes}',source)
        self.assertNotIn(f'calldatacopy(256,0,{c.prefix})',source)
        self.assertIn(f'calldatacopy({256+32*len(used)},{32*c.registers},288)',source)
        self.assertEqual(len(written),8)
        for value in inputs:self.assertIn(f'calldataload({32*value})',source)
        # The eight-word root seed is exported as eight distinct updates.
        self.assertIn('let response := mload(0x40)',source)
        for j,value in enumerate(written):self.assertIn(f'mstore(add(response,{288+64*j}),{32*value})',source)

    def test_shape_error_compaction_changes_only_diagnostics(self):
        for name in ['StackedWhir.sol','KoalaBear.sol','KeccakTranscript.sol']:
            source=(HERE.parent/'src'/name).read_text()
            compact=m.compact_shape_errors(source,'NativeShape')
            compact=compact.replace('\n    error NativeShape();\n','').replace('NativeShape()','"diagnostic"')
            # Normalize only the final string argument of each original require.
            normalized=re.sub(r',\s*"[^"\\]*"\s*\)',',"diagnostic")',source)
            self.assertEqual(compact,normalized)

    def test_native_transcript_retains_public_checks_and_independent_original(self):
        original=(HERE.parent/'src/KeccakTranscript.sol').read_text()
        fast=m.native_transcript(original)
        for name in ('create','observe','observeHash','sample','bits','grind'):
            self.assertEqual(m.block(original,'function '+name+'('),m.block(fast,'function '+name+'('))
        for source in (original,fast):self.assertIn('"canonical transcript extension"',m.block(source,'function observeE('))
        self.assertEqual(m.block(original,'function observeE(').split('        uint256 value;',1)[1],
                         m.block(fast,'function observeE(').split('        uint256 value;',1)[1])
        for source in (original,fast):
            self.assertIn('require(buffered.length < 100 && wordsLeft <= 8, "transcript shape")',source)
        self.assertIn('8 - s.wordsLeft',m.block(fast,'function word('))
        self.assertEqual(m.block(fast,'function sampleE(').count('sample(s)'),4)
        self.assertIn('if gt(pending,100)',m.block(fast,'function append('))
        self.assertNotIn('mcopy(add(payload,64)',original)

    def test_yul_optimizer_runs_are_part_of_the_pinned_input(self):
        small=json.loads(m.compiler_input('object "x" { code { stop() } }','x','full',1))
        previous=json.loads(m.compiler_input('object "x" { code { stop() } }','x','full',200))
        self.assertEqual(small['settings']['optimizer']['runs'],1)
        self.assertEqual(previous['settings']['optimizer']['runs'],200)
        previous['settings']['optimizer']['runs']=1
        self.assertEqual(small,previous)

    def test_direct_wire_observations_retain_bounds_and_computed_checks(self):
        c=self.compiler
        for opcode,tag,count in [(10,0x40000000,4),(11,0x20000000,16)]:
            at=next(i for i,op in enumerate(c.ops) if op[0]==opcode and op[2]&0xf0000000==tag)
            value=c.ops[at][2]
            source=c.kernel(at,at+1,'ObserveWire')
            self.assertIn(f'append(calldataload({c.packet+38+4*(value&0x0fffffff)}),{count})',source)
            altered=copy.copy(c);altered.ops=[[opcode,0,tag+c.meta['field_count']]]
            with self.assertRaises(AssertionError):altered.kernel(0,1,'OutOfBounds')
        at=next(i for i,op in enumerate(c.ops) if op[0]==11 and op[2]<c.registers)
        source=c.kernel(at,at+1,'ObserveComputed')
        self.assertIn('observeE(mload(',source)

    def test_packed_arithmetic_type_preconditions(self):
        c=copy.copy(self.compiler)
        for ops in [
            [[4,0,0x10000000,0x80000001]],
            [[7,0,0x10000000]],
            [[23,0,0x80000001,0x20000000]],
            [[20,0,0x20000000,0x80000001]],
            [[15,0,1<<255],[10,0,0]],
            [[15,0,1<<255],[4,0,0,0x80000001]],
        ]:
            c.ops=ops
            with self.assertRaises(AssertionError):c.check_arithmetic_types()
        # Seeding reads its hash before replacing the aliased eight registers
        # with canonical base fields, which may then serve as scalar operands.
        c.ops=[[15,0,1<<255],[16,0,0],[13,8],[23,9,8,0],[11,0,9]]
        c.check_arithmetic_types()

    def test_native_field_copy_replaces_only_add_and_sub(self):
        source=(HERE.parent/'src/KoalaBear.sol').read_text()
        transformed=m.native_field_library(source)
        for name in ('add','sub'):
            source=source.replace(m.block(source,'function '+name+'('),'<'+name+'>')
            transformed=transformed.replace(m.block(transformed,'function '+name+'('),'<'+name+'>')
        self.assertEqual(source,transformed)

    def test_tower_field_copy_preserves_other_reference_operations(self):
        source=(HERE.parent/'src/KoalaBear.sol').read_text()
        transformed=m.native_field_library(source,tower_mulmod=True)
        for name in ('add','sub','mul'):
            source=source.replace(m.block(source,'function '+name+'('),'<'+name+'>')
            transformed=transformed.replace(m.block(transformed,'function '+name+'('),'<'+name+'>')
        self.assertEqual(source,transformed)

    def test_checked_facts_preserve_order_overwrites_and_rejection(self):
        import random
        from reference import Reference
        c=copy.copy(self.compiler)
        e,f,lit=0x20000000,0x40000000,0x80000000
        original=[
            [6,0,e,e+4],[8,0,e,lit],[6,1,e,e+4],
            [8,0,f+4,lit+1],[6,2,e+4,f+4],
            [8,0,e+8,lit+1],[6,3,e+4,e+8],
            [4,4,lit+3,lit+2],[8,0,4,f+12],[6,5,4,e+4],
            [13,4],[6,6,4,e+4],[4,4,lit+1,lit],
            [6,4,4,e+4],[6,7,4,e+4],[5,9,e+4,e+4],[11,0,e+8],
        ]
        c.ops=copy.deepcopy(original);c.check_arithmetic_types();c.specialize_assertions()
        self.assertEqual(c.ops[0],original[0])  # no fact before its assertion
        self.assertEqual(c.ops[2],[4,1,lit,lit])
        self.assertEqual([x for x in c.ops if x[0]==8],[x for x in original if x[0]==8])
        self.assertEqual(c.ops[-1],original[-1])
        self.assertEqual(c.ops[11][2],4)  # RNG overwrote the former scalar
        self.assertEqual(c.ops[14][2],4)  # aliased multiplication overwrote one
        self.assertNotIn(0,c.constant_preconditions(1)['fields'])
        self.assertEqual(c.constant_preconditions(2)['fields'][0],0)
        self.assertNotIn(4,c.constant_preconditions(11)['registers'])
        rng=random.Random(721731)
        raw=bytearray(38+4*16)
        def put(packet,index,value):packet[38+4*index:42+4*index]=value.to_bytes(4,'little')
        def run(ops,packet):
            manifest=dict(self.manifest,ops=ops,metadata=dict(self.manifest['metadata'],field_count=16,hash_count=0))
            model=Reference(manifest,packet,bytes(32));model.run(0,len(ops));return model
        for _ in range(96):
            packet=bytearray(raw)
            for index in range(16):put(packet,index,rng.randrange(m.P))
            for index in range(4):put(packet,index,0)
            put(packet,4,1)
            for index in range(8,12):put(packet,index,1 if index==8 else 0)
            put(packet,12,5)
            before,after=run(original,packet),run(c.ops,packet)
            self.assertEqual(before.regs,after.regs)
            self.assertEqual((before.t.digest,before.t.buffer,before.t.left),(after.t.digest,after.t.buffer,after.t.left))
            for index in (0,4,8,11,12):
                bad=bytearray(packet);put(bad,index,(int.from_bytes(bad[38+4*index:42+4*index],'little')+1)%m.P)
                for ops in (original,c.ops):
                    with self.assertRaisesRegex(ValueError,'assertion'):run(ops,bad)

    def test_proof_cache_selects_only_executed_extension_reads(self):
        c=copy.copy(self.compiler);e,lit=0x20000000,0x80000000
        c.ops=[[11,0,e+24],[4,0,e,lit],[6,1,lit,e+4],[8,0,e+8,e+12]]
        c.prepare_proof_cache()
        self.assertEqual(c.proof_cache_indices,[0,8,12])
        self.assertEqual(c.context_bytes,c.packet+c.wire_bytes+3*16+16)
        self.assertEqual(c.proof_cache_ranges,(0).to_bytes(4,'big')+(1).to_bytes(2,'big')+(8).to_bytes(4,'big')+(2).to_bytes(2,'big'))
        self.assertIn('reverse128',c.ref(e+24))
        self.assertEqual(c.ref(e+8),f'shr(128,calldataload({c.packet+c.wire_bytes+16}))')

    def test_dead_arithmetic_preserves_observables_overwrites_and_inverse_guards(self):
        import random
        from reference import Reference
        rng=random.Random(9183003);e,lit=0x20000000,0x80000000
        terminal={0,1,3,8,10};pool=[0,1,3,4,5,6,7,8,9,10,11]
        for case in range(48):
            ops=[[8,0,e,lit+1],[15,2,0x12345678],[16,4,2],[13,11],[4,11,lit,lit]]
            for j in range(160):
                dst=rng.choice(pool);a=rng.choice(pool+[e+4,e+8,lit,lit+1,lit+7]);b=rng.choice(pool+[e+4,e+8,lit,lit+1])
                ops.append([rng.choice([4,5,6]),dst,a,b])
                if j%23==0:ops.append([11,0,rng.choice(pool)])
                if j%29==0:ops.append([8,0,dst,dst])
            ops.extend([[6,2,e+4,e+8],[7,2,e+4],[4,2,lit,lit],[13,2]])
            c=copy.copy(self.compiler);c.ops=ops;c.check_arithmetic_types();c.eliminate_dead_arithmetic(terminal)
            reduced=[[4,op[1],op[1],lit] if i in c.dead_ops else op for i,op in enumerate(ops)]
            self.assertTrue(c.dead_ops)
            self.assertNotIn(len(ops)-3,c.dead_ops)  # unused inverse must still reject zero
            self.assertNotIn(len(ops)-1,c.dead_ops)  # unused RNG draw still changes transcript
            self.assertTrue(all(ops[i][0] in (4,5,6,15,16,18,20,21,22,23) for i in c.dead_ops))
            packet=bytearray(38+16*4)
            for j in range(16):packet[38+4*j:42+4*j]=rng.randrange(1,m.P).to_bytes(4,'little')
            packet[38:54]=(1).to_bytes(16,'little')
            def model(program,data):return Reference(dict(self.manifest,ops=program,metadata=dict(self.manifest['metadata'],field_count=16,hash_count=0)),data,bytes(32))
            before,after=model(ops,packet),model(reduced,packet)
            at=0
            for end in (3,17,53,111,len(ops)):
                before.run(at,end);after.run(at,end);at=end
                for reg in c.live_registers(end):self.assertEqual(before.regs[reg],after.regs[reg],(case,end,reg))
                self.assertEqual((before.t.digest,before.t.buffer,before.t.left),(after.t.digest,after.t.buffer,after.t.left))
            for reg in terminal:self.assertEqual(before.regs[reg],after.regs[reg])
            for index,expected in ((0,'assertion'),(4,'zero inverse')):
                bad=bytearray(packet)
                bad[38+4*index:54+4*index]=(2 if index==0 else 0).to_bytes(16,'little')
                for program in (ops,reduced):
                    with self.assertRaisesRegex(ValueError,expected):model(program,bad).run(0,len(program))

    def test_bulk_observations_stop_at_gaps_registers_and_effects(self):
        c=copy.copy(self.compiler);f,e=0x40000000,0x20000000
        c.ops=[[10,0,f+2],[11,0,e+3],[10,0,f+7],[13,1],[11,0,e+8]]
        self.assertEqual(c.observation_run(0,5),(3,f'appendProof({c.packet+38+8},24)'))
        c.ops[2]=[10,0,f+8]
        self.assertEqual(c.observation_run(0,5),(2,f'appendProof({c.packet+38+8},20)'))
        c.ops[1]=[11,0,0]
        self.assertIsNone(c.observation_run(0,5))

    def test_closing_split_preserves_preclosing_verification_and_runtime_binding(self):
        config=parse(self.compiler.tail)[0]
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        source=m.native_whir_library(m.recycle_whir_scratch(source))
        source=m.specialize_whir_generators(m.native_merkle_path_views(source),config)
        source=m.fused_base_whir(source,config)
        transformed=m.closing_module_whir(source)
        before=source[:source.index('        uint256 total;',source.index('    function verify('))]
        after=transformed[:transformed.index('        uint256 words;',transformed.index('    function verify('))]
        expected=before.replace('import {KoalaBear as F}', 'import {INativeClosingEvaluator} from "./INativeClosingEvaluator.sol";\nimport {KoalaBear as F}',1)
        expected=expected.replace('        T.State memory t\n    ) internal pure {','        T.State memory t, address closingModule\n    ) internal view {',1)
        expected=expected.replace('                stirPoints[q] = N.basePowers(F.basePow(g, indices[q]), rem);','                stirPoints[q] = new uint256[](1);\n                stirPoints[q][0] = F.basePow(g, indices[q]);',1)
        self.assertEqual(expected,after)
        self.assertIn('if (total != w.claim) revert InvalidWhir(5);',transformed)
        c=copy.copy(self.compiler);c.closing_module_hash='0x'+'11'*32
        tail,entry=split_sources(entry_source(c,'00'*32,128))
        self.assertIn('closingModule.codehash=='+c.closing_module_hash,tail)
        self.assertIn('closing.codehash=='+c.closing_module_hash,entry)
        self.assertIn('tail.verifyContext(context,closingModule)',entry)
        self.assertNotIn('import {NativeClosingEvaluator}',tail)

    def test_hash_register_cannot_enter_whir_point(self):
        c=copy.copy(self.compiler)
        c.final_register_kinds=c.final_register_kinds[:]
        _,_,_,point,_=parse(c.tail)
        register=next(value for value in point if value<self.compiler.registers)
        c.final_register_kinds[register]='H'
        with self.assertRaisesRegex(AssertionError,'noncanonical WHIR field reference'):
            entry_source(c,'00'*32,128)

    def test_calldata_conversion_preserves_protocol_and_full_leaf_checks(self):
        config=parse(self.compiler.tail)[0]
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        source=m.native_whir_library(m.recycle_whir_scratch(source))
        source=m.specialize_whir_generators(m.native_merkle_path_views(source),config)
        source=m.closing_module_whir(m.fused_base_whir(source,config))
        converted=m.calldata_whir(source,self.compiler.wire_bytes)
        # All protocol rounds, equations, transcript draws, grinding and the
        # closing equality are identical; only leaf storage/readers change.
        self.assertEqual(m.block(source,'function verify('),m.block(converted,'function verify('))
        before=m.block(source,'function checkMerkle(')
        after=m.block(converted,'function checkMerkle(')
        for statement in ('checkMemory(start,div(byteCount,4),invalidField)',
                          'h := keccak256(start,byteCount)',
                          'if(h!=root) revert InvalidWhir(2)'):
            self.assertIn(statement,before);self.assertIn(statement,after)
        self.assertIn('NativeMerklePath.walkCalldata(h,index,height,pathPointer)',after)
        c=copy.copy(self.compiler);c.closing_module_hash='0x'+'11'*32;c.calldata_tail=True
        tail,entry=split_sources(entry_source(c,'00'*32,128,path_views=True,fused_base=True))
        self.assertIn(f'bytes calldata packet=context[{c.packet}:]',tail)
        self.assertIn(f'serialized.length=={c.packet+c.wire_bytes}',tail)
        self.assertNotIn('bytes memory context=serialized',tail)
        self.assertIn('Wire.validateFields(wire,38,',entry)

    def test_branchless_products_use_complete_original_formulas(self):
        source=m.helpers(0,False,tower_mulmod=True)+m.wide_dot_helpers()+m.matrix_helpers(True)
        result=m.branchless_product_helpers(source)
        # Only the fast-return branches disappear. Keep reductions, bounds,
        # inversion rejection, transcript checks and every other helper intact.
        for name in ('times','wideTimes','matrixTimes'):
            original=m.block(source,'function '+name+'(')
            condition='if lt(a,2)' if name=='matrixTimes' else 'if or(lt(packedLeft,2)'
            expected=original.replace(m.block(original,condition),'',1)
            self.assertEqual(m.block(result,'function '+name+'('),expected)
            source=source.replace(original,expected,1)
        self.assertEqual(source,result)

    def test_partial_round_loop_retains_all_authenticated_constants(self):
        data=next(op[-1] for op in self.manifest['ops'] if op[0]==18)
        original=m.specialized_poseidon(data);looped=m.specialized_poseidon(data,True)
        self.assertEqual(m.block(original,'function linear('),m.block(looped,'function linear('))
        encoded=bytes.fromhex(data);keys=b''.join(encoded[64*r:64*r+4] for r in range(4,24))
        for offset in range(0,96,32):
            word=keys[offset:offset+32].ljust(32,b'\0')
            self.assertIn(f'mstore(add(constants,{offset}),0x{word.hex()})',looped)
        for r in list(range(4))+list(range(24,28)):
            for i in range(16):
                value=int.from_bytes(encoded[64*r+4*i:64*r+4*i+4],'big')
                statement=f'{{let x:=add(mload(add(state,{32*i})),{value}) mstore(add(state,{32*i}),mod(mul(mul(x,x),x),{m.P}))}}'
                self.assertEqual(looped.count(statement),original.count(statement))
        self.assertEqual(looped.count('for{let step:=0}lt(step,20)'),1)
        self.assertIn('shr(224,mload(add(constants,mul(step,4))))',looped)

    def test_compact_optimizer_request_is_pinned(self):
        request=json.loads(m.compiler_input('object "A" {code{stop()}}','A','compact',1))
        details=request['settings']['optimizer']['details']['yulDetails']
        self.assertTrue(details['stackAllocation'])
        self.assertEqual(details['optimizerSteps'],'dhfoD[xarrscLMcCTU]uljmul:fDnTOcmu')
        self.assertNotIn('i',details['optimizerSteps'])
        self.assertEqual(request['settings']['evmVersion'],'prague')

    def test_streamed_query_rows_keep_checks_and_owned_scratch(self):
        source=m.matrix_query_evaluator((m.ROOT/'src/NativeQueryEvaluator.sol').read_text())
        result=m.stream_query_evaluator(source)
        self.assertEqual(m.block(source,'function foldInitial('),m.block(result,'function foldInitial('))
        before=m.block(source,'function foldRows(');after=m.block(result,'function foldRows(')
        marker='uint256[] memory matrices=prepareCoordinates(point);'
        self.assertEqual(before[:before.index('bytes memory packed=fields;')],after[:after.index(marker)])
        self.assertIn('uint256[] memory row=new uint256[](width>>1)',after)
        self.assertIn('foldStream(fields,q*stride,width,matrices,row)',after)
        self.assertNotIn('packedExtensions',after)
        self.assertEqual(m.block(result,'function prepareCoordinates('),m.block(source,'function prepareCoordinates('))
        self.assertEqual(m.block(result,'function matrixTimes('),m.block(source,'function matrixTimes('))
        self.assertEqual(m.block(result,'function reversePair('),m.block((m.ROOT/'src/NativeProofCache.sol').read_text(),'function reversePair('))
        self.assertIn('case 1 {folded:=shr(128,reversePair(calldataload(source)))}',result)
        self.assertIn('mstore(dst,plus(a,matrixTimes(minus(b,a),at)))',result)

    def test_query_matrices_are_private_and_preserve_external_checks(self):
        source=(m.ROOT/'src/NativeQueryEvaluator.sol').read_text()
        result=m.matrix_query_evaluator(source)
        self.assertEqual(m.block(source,'function foldInitial('),m.block(result,'function foldInitial('))
        before=m.block(source,'function foldRows(')
        after=m.block(result,'function foldRows(')
        self.assertEqual(before[:before.index('bytes memory packed=fields;')],after[:after.index('bytes memory packed=fields;')])
        self.assertIn('prepareCoordinates(point)',after)
        self.assertIn('foldPrepared(F.packedExtensions(packed,q*stride,width),matrices)',after)
        self.assertIn('new uint256[](5*point.length)',result)
        self.assertEqual(m.block(result,'function prepareMatrix('),m.block(m.matrix_helpers(True),'function prepareMatrix('))
        self.assertEqual(m.block(result,'function matrixTimes('),m.block(m.matrix_helpers(True),'function matrixTimes('))
        for name in ('plus','minus'):
            self.assertEqual(m.block(result,'function '+name+'('),m.block((m.ROOT/'src/NativeFieldArithmetic.sol').read_text(),'function '+name+'('))

    def test_query_offload_retains_authentication_and_only_uses_contiguous_fields(self):
        config=parse(self.compiler.tail)[0]
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        source=m.native_whir_library(m.recycle_whir_scratch(source))
        source=m.specialize_whir_generators(m.native_merkle_path_views(source),config)
        source=m.calldata_whir(m.closing_module_whir(m.fused_base_whir(source,config)),self.compiler.wire_bytes)
        result=m.offload_query_whir(source)
        self.assertEqual(m.block(source,'function checkMerkle('),m.block(result,'function checkMerkle('))
        self.assertEqual(re.findall(r'\bt\.\w+\([^;]*;',source),re.findall(r'\bt\.\w+\([^;]*;',result))
        for stage in (3,4,5):self.assertIn(f'InvalidWhir({stage})',result)
        c=copy.copy(self.compiler);c.calldata_tail=True;c.offload_queries=True;c.closing_module_hash='0x'+'11'*32
        tail,_=split_sources(entry_source(c,'00'*32,128,path_views=True,fused_base=True))
        cfg,roots,stripes,point,proof=parse(c.tail)
        for i,group in enumerate(proof['openings']):
            refs=[v for leaf in group for row in leaf['values'] for v in row];first=refs[0]&0x0fffffff
            self.assertIn(f'p.dataViews[{2*i}]=packetOffset+{38+4*first};p.dataViews[{2*i+1}]={4*len(refs)};',tail)
        bad=copy.deepcopy(proof)
        for leaf in bad['openings'][0][1::len(roots)]:
            leaf['values']=[[ref+4 for ref in row] for row in leaf['values']]
        with patch('wire.parse',return_value=(cfg,roots,stripes,point,bad)):
            with self.assertRaisesRegex(AssertionError,'contiguous range'):
                entry_source(c,'00'*32,128,path_views=True,fused_base=True)

    def test_literal_identities_preserve_reads_writes_and_assertions(self):
        c=copy.copy(self.compiler)
        c.ops=[[4,2,2,0x80000000],[4,3,0x20000000,0x80000000],
               [6,4,0x80000000,5],[6,6,7,0x80000001],[8,0,2,3]]
        inputs,written,used=c.register_access(0,len(c.ops))
        self.assertEqual(inputs,[2,7])
        self.assertEqual(written,[3,4,6])
        self.assertEqual(used,[2,3,4,6,7])
        self.assertIsNone(c.identity_source([8,0,0x80000000,0x80000000]))
        self.assertIsNone(c.identity_source([4,2,2,0x40000000]))
        self.assertEqual(c.identity_source([5,0,1,0x80000000]),1)

    def test_affine_loops_preserve_pair_order_and_address_progressions(self):
        c=copy.copy(self.compiler)
        c.ops=[op for i in range(6) for op in [[6,1,10+i,0x20000000+4*i],[4,0,0,1]]]
        slots={value:i for i,value in enumerate([0,1,*range(10,16)])}
        count,source=c.arithmetic_loop(0,len(c.ops),slots)
        self.assertEqual(count,6)
        self.assertIn('mul(j,32)',source);self.assertIn('mul(j,16)',source)
        # Commuting addition inputs is valid; crossing an assertion is not.
        c.ops[1]=[4,0,1,0]
        self.assertEqual(c.arithmetic_loop(0,len(c.ops),slots)[0],6)
        c.ops[5]=[8,0,0,1]
        self.assertIsNone(c.arithmetic_loop(0,len(c.ops),slots))

    def test_affine_loops_reject_nonaffine_local_maps_and_handle_reverse_reads(self):
        c=copy.copy(self.compiler)
        c.ops=[op for i in range(6) for op in [[6,1,10+i,0x20000000+4*(5-i)],[4,0,0,1]]]
        slots={value:i for i,value in enumerate([0,1,*range(10,16)])}
        count,source=c.arithmetic_loop(0,len(c.ops),slots)
        self.assertEqual(count,6);self.assertIn('sub(',source)
        slots[11]=100
        self.assertIsNone(c.arithmetic_loop(0,len(c.ops),slots))

    def test_delayed_dot_reductions_reject_feedback_and_respect_liveness(self):
        c=copy.copy(self.compiler);c.fused_dot=True
        c.ops=[op for i in range(6) for op in [[6,1,10+i,0x20000000+4*i],[4,0,0,1]]]
        slots={value:i for i,value in enumerate([0,1,*range(10,16)])}
        count,source=c.arithmetic_loop(0,len(c.ops),slots)
        self.assertEqual(count,6);self.assertIn('wideTimes(',source)
        self.assertIn('if eq(j,5)',source) # Preserve final temporary version.
        c.live_masks=[0]*(len(c.ops)+1)
        self.assertNotIn('if eq(j,5)',c.arithmetic_loop(0,len(c.ops),slots)[1])
        for aliased in (0,1):
            c.ops=[op for i in range(6) for op in [[6,1,aliased,0x20000000+4*i],[4,0,0,1]]]
            source=c.arithmetic_loop(0,len(c.ops),slots)[1]
            self.assertNotIn('wideTimes(',source)
            self.assertIn('times(',source)
        c.ops=[op for i in range(9) for op in [[6,1,8-i,0x20000000+4*i],[4,0,0,1]]]
        self.assertNotIn('wideTimes(',c.arithmetic_loop(0,len(c.ops),{i:i for i in range(9)})[1])

    def test_matrix_cache_tracks_every_register_overwrite_and_operand_side(self):
        c=copy.copy(self.compiler);c.matrix_cache=True;c.matrix_min_uses=4
        before=[[6,100+i,2,10+i] for i in range(4)]
        after=[[6,104+i,14+i,2] for i in range(4)]
        for overwrite in ([4,2,3,0x80000000],[13,2],[16,2,0x10000000],[18,2,0,1,'00']):
            c.ops=before+[overwrite]+after
            _,_,used=c.register_access(0,len(c.ops));plan,factors=c.matrix_plan(0,len(c.ops),{v:i for i,v in enumerate(used)})
            self.assertEqual(len(factors),2)
            self.assertNotEqual(factors[0][0],factors[1][0])
            self.assertEqual({plan[i][1] for i in range(4)},{0})
            self.assertEqual({plan[i][1] for i in range(5,9)},{1})
            self.assertEqual(sum(record[2] for record in plan.values()),2)

    def test_lazy_linear_products_normalize_strict_uses_and_exports(self):
        c=copy.copy(self.compiler);c.ops=[[4,0,1,2],[4,3,4,5],[6,6,0,3],[5,7,0,1],[8,0,7,7],[11,0,6],[15,0,(1<<256)-17],[12,0,0]]
        c.pcs=list(range(len(c.ops)));c.tower_mulmod=True;c.branchless_products=True;c.lazy_linear_products=True
        _,_,used=c.register_access(0,len(c.ops));slots={v:i for i,v in enumerate(used)}
        source=c.kernel(0,len(c.ops),'LazyBounds')
        raw=lambda r:'mload('+str(256+32*slots[r])+')'
        self.assertIn('times('+raw(0)+','+raw(3)+')',source)
        self.assertIn('eqCheck(4,reducePacked('+raw(7)+'),reducePacked('+raw(7)+'))',source)
        self.assertIn('append('+raw(0)+',32)',source) # Full-width hash overwrite clears slack.
        self.assertIn('function reducePacked(value)->out',source)
        self.assertLess(2*m.P-1+((1<<31)-m.P),1<<32)
        self.assertLess(64*m.P*m.P*1024,1<<128)
        c.branchless_products=False
        with self.assertRaises(AssertionError):c.kernel(0,len(c.ops),'InvalidLazy')

    def test_lazy_linear_intervals_only_change_fully_selected_kernels(self):
        c=copy.copy(self.compiler);c.ops=[[4,0,1,2],[6,3,0,2]];c.pcs=[0,1];c.tower_mulmod=True;c.branchless_products=True
        baseline=c.kernel(0,2,'SpanCase')
        c.lazy_linear_products=True;c.lazy_linear_spans=[[1,2]]
        self.assertEqual(c.kernel(0,2,'SpanCase'),baseline)
        c.lazy_linear_spans=[[0,2]]
        selected=c.kernel(0,2,'SpanCase')
        self.assertNotEqual(selected,baseline)
        self.assertIn('function reducePacked(value)->out',selected)

    def test_lazy_matrix_inputs_are_canonicalized_and_loop_feedback_is_bounded(self):
        c=copy.copy(self.compiler);c.ops=[[4,0,1,2]]+[[4,16+i,i,32+i] for i in range(12)]+[[6,64+i,0,16+i] for i in range(12)]
        c.pcs=list(range(len(c.ops)));c.tower_mulmod=True;c.branchless_products=True;c.lazy_linear_products=True;c.matrix_cache=True;c.matrix_min_uses=8;c.matrix_left_only=True
        _,_,used=c.register_access(0,len(c.ops));slots={v:i for i,v in enumerate(used)}
        source=c.kernel(0,len(c.ops),'LazyMatrix')
        self.assertIn('prepareMatrix(reducePacked(mload('+str(256+32*slots[0])+'))',source)
        self.assertIn('matrixTimes(reducePacked(',source)

    def test_derived_query_variants_keep_checked_methods_and_all_shape_predicates(self):
        source=(HERE.parent/'src/NativeQueryEvaluator.sol').read_text()
        source=m.canonical_query_evaluator(source);updated=m.derived_query_inputs(source)
        for name in ('foldInitial','foldRows'):
            self.assertEqual(m.block(source,'function '+name+'('),m.block(updated,'function '+name+'('))
        for text in ['if(lambdaPowers[r].length>32767)revert InvalidClosingInput();','if(stride==0 || fields.length%stride!=0)revert InvalidClosingInput();','if(point.length>24)revert InvalidClosingInput();','if(fields.length%stride!=0)revert InvalidClosingInput();']:
            self.assertIn(text,updated)
        for name in ('foldInitialCanonical','foldRowsCanonical'):
            self.assertNotIn('F.canonical(',m.block(updated,'function '+name+'('))
        self.assertEqual(source.count('Wire.validateFields('),updated.count('Wire.validateFields('))

    def test_query_canonical_derivations_reject_overwrites_and_changed_samples(self):
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        m.check_query_parameter_derivations(source)
        for before,after in [('uint256 lambda = t.sampleE();','uint256 lambda = 0;'),('lp = F.mul(lp, lambda);','lp = lambda;'),('w.randomness[w.folded++] = x;','w.randomness[w.folded++] = 1;')]:
            with self.assertRaises(AssertionError):m.check_query_parameter_derivations(source.replace(before,after))
        with self.assertRaises(AssertionError):m.check_query_parameter_derivations(source.replace('uint256[] memory foldPoint = F.slice(w.randomness, start, rc.fold);','uint256[] memory foldPoint = F.slice(w.randomness, start, rc.fold);foldPoint[0]=0;'))

    def test_packed_canonical_changes_only_the_exact_original_predicate(self):
        source=(HERE.parent/'src/KoalaBear.sol').read_text();updated=m.packed_canonical_library(source)
        self.assertEqual(source.replace(m.block(source,'function canonical('),'<canonical>'),updated.replace(m.block(updated,'function canonical('),'<canonical>'))
        self.assertIn('iszero(or(shr(128,a),flags))',updated)
        with self.assertRaises(AssertionError):m.packed_canonical_library(source.replace('uint32(a) < P','uint32(a) <= P'))

    def test_native_cache_module_uses_exact_reverse_and_approved_field_ranges(self):
        c=copy.copy(self.compiler);c.prepare_proof_cache()
        source=m.proof_cache_module_source(c)
        original=(HERE.parent/'src/NativeProofCache.sol').read_text()
        self.assertEqual(m.block(source,'function reversePair('),m.block(original,'function reversePair('))
        self.assertIn('eq(calldatasize(),'+str(4*c.meta['field_count'])+')',source)
        self.assertIn('return(0,'+str(16*len(c.proof_cache_indices)+16)+')',source)
        ranges=c.proof_cache_ranges
        rebuilt=[]
        for at in range(0,len(ranges),6):
            first=int.from_bytes(ranges[at:at+4],'big');count=int.from_bytes(ranges[at+4:at+6],'big')
            rebuilt.extend(range(first,first+4*count,4))
        self.assertEqual(rebuilt,c.proof_cache_indices)
        c.proof_cache_ranges=(c.meta['field_count']+1).to_bytes(4,'big')+bytes([0,1])
        with self.assertRaises(AssertionError):m.proof_cache_module_source(c)

    def test_native_cache_entry_owns_staging_and_preserves_full_packet_initialization(self):
        c=copy.copy(self.compiler);c.prepare_proof_cache();c.inplace_tail=True;c.closing_module_hash='0x'+'11'*32
        _,source=split_sources(entry_source(c,'00'*32,128,path_views=True))
        result=m.offload_cache_entry(source,c,{'runtime':'00','bytecode':'00'})
        self.assertIn('Wire.validateFields(wire,38,',result)
        self.assertLess(result.index('Wire.validateFields'),result.index('staticcall(gas(),cacheTarget'))
        self.assertLess(result.index('staticcall(gas(),cacheTarget'),result.index('Dictionary.decodeInto'))
        self.assertIn('calldatacopy(add(at,'+str(c.packet)+'),wire.offset,wire.length)',result)
        self.assertIn('createdCache.codehash==0x'+m.kh(bytes([0])).hex(),result)
        self.assertIn('proofCacheModule=createdCache;',result)
        self.assertIn('returndatasize(),'+str(16*len(c.proof_cache_indices)+16),result)
        # Full packet, cache and prefix offsets remain identical to all kernels.
        self.assertIn('add(add(context,32),'+str(c.packet+c.wire_bytes)+')',result)
        self.assertEqual(m.block(source,'function _finish('),m.block(result,'function _finish('))

    def test_direct_update_frames_keep_size_alignment_and_immutable_bounds(self):
        original=(HERE.parent/'src/NativeTerminalVerifier.sol').read_text()
        source=m.direct_register_updates(original)
        self.assertNotIn('new bytes(_maxReturnLength())',source)
        self.assertIn('returned < 288 || returned > maxReturnLength || (returned - 288) % 64 != 0',source)
        self.assertIn('if or(iszero(lt(offset, registers)), and(offset, 31))',source)
        self.assertIn('returndatacopy(add(state, registers), 0, 288)',source)
        self.assertIn('returndatacopy(0, at, 64)',source)
        self.assertIn('mstore(add(state, offset), mload(32))',source)
        # Input still uses the whole immutable context; no delegatecall or
        # proof-supplied acceptance flag replaces any pinned kernel call.
        self.assertIn('staticcall(gas(), kernel, add(context, 32), mload(context), 0, 0)',source)
        self.assertIn('revert(at, returned)',source)
        self.assertEqual(m.block(original,'constructor(address[]'),m.block(source,'constructor(address[]'))

    def test_whir_recycling_changes_only_scratch_lifetimes(self):
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        transformed=m.recycle_whir_scratch(source)
        stripped=re.sub(r'^\s*uint256 (?:query|finalQuery|identity)Scratch;\n','',transformed,flags=re.M)
        stripped=re.sub(r'^\s*assembly\("memory-safe"\)\{(?:queryScratch|finalQueryScratch|identityScratch):=mload\(0x40\)\}\n','',stripped,flags=re.M)
        stripped=re.sub(r'^\s*assembly\("memory-safe"\)\{mstore\(0x40,(?:queryScratch|finalQueryScratch|identityScratch)\)\}\n','',stripped,flags=re.M)
        self.assertEqual(source,stripped)
        # The only newly persistent allocation in the query loop follows reset.
        self.assertLess(transformed.index('mstore(0x40,queryScratch)'),transformed.index('stirPoints[q] = F.powers'))

    def test_native_whir_retains_every_other_predicate_and_original_field_error(self):
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        transformed=m.native_whir_library(source)
        before=m.block(source,'assembly ("memory-safe") {\n                let start := add(add(source, 32), offset)')
        after=m.block(transformed,'assembly ("memory-safe") {\nfunction checkMemory(')
        self.assertEqual(source.replace(before,'<packed validation>'),transformed.replace(after,'<packed validation>'))
        self.assertIn('checkMemory(start,div(byteCount,4),invalidField)',after)
        self.assertIn('bytes4 invalidField = F.InvalidField.selector;',transformed)

    def test_path_views_retain_leaf_validation_and_full_verifier_flow(self):
        source=(HERE.parent/'src/StackedWhir.sol').read_text()
        transformed=m.native_merkle_path_views(source)
        # The verification algorithm, leaf folding and canonical leaf hashing
        # are unchanged. Only path addressing/iteration and struct fields move.
        for marker in ('function verify(', 'function virtualLeaf(', 'if (leaf.source.length != 0) {'):
            self.assertEqual(m.block(source,marker),m.block(transformed,marker))
        self.assertIn('leaf.pathView>>32==height',transformed)
        self.assertIn('height<=(leaf.source.length-pathOffset)/32',transformed)
        self.assertIn('require(leaf.path.length==height',transformed)
        self.assertIn('if (h != root) revert InvalidWhir(2);',transformed)

    def test_path_decoder_uses_only_approved_hash_section_views(self):
        c=self.compiler
        source=entry_source(c,'00'*32,128,path_views=True)
        cfg,roots,stripes,point,proof=parse(c.tail)
        self.assertIn('new bytes32[](0),packet,',source)
        for group in proof['openings']:
            for leaf in group:
                refs=leaf['path'];first=refs[0]&0x0fffffff
                self.assertTrue(all(ref&0xf0000000==0x10000000 for ref in refs))
                self.assertEqual(refs,list(range(refs[0],refs[0]+len(refs))))
                self.assertLessEqual(first+len(refs),c.meta['hash_count'])
                offset=38+4*c.meta['field_count']+32*first
                descriptor=offset|(len(refs)<<32)
                self.assertEqual(descriptor&0xffffffff,offset)
                self.assertEqual(descriptor>>32,len(refs))

    def test_specialized_generators_match_all_reachable_original_domains(self):
        source=(HERE.parent/'src/StackedWhir.sol').read_text();config=parse(self.compiler.tail)[0]
        transformed=m.specialize_whir_generators(source,config)
        expected={17:0x163bd499,19:0x143ef899,21:0x484ef19b,23:0x68e7dd49,24:0x6ac49f88}
        for height,value in expected.items():
            self.assertEqual(value,pow(3,(m.P-1)>>height,m.P))
            self.assertIn(f'if(log=={height}) return {value};',transformed)
        original=m.block(source,'function generator(');replacement=m.block(transformed,'function generator(')
        self.assertEqual(source.replace(original,'<generator>'),transformed.replace(replacement,'<generator>'))


if __name__=='__main__':
    FIXTURE=Path(sys.argv.pop(1)).resolve()
    unittest.main()
