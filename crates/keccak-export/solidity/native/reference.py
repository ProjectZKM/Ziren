"""Independent Python execution model for native-kernel checkpoint parity.

Used only in local validation. The contract does not accept this model's output.
The final transcript and opening point are also checked against the authenticated
Rust export, rather than relying solely on this interpreter.
"""
from Crypto.Hash import keccak

P=0x7f000001
MASK=(1<<32)-1


def kh(data):
    return keccak.new(digest_bits=256,data=data).digest()


def lanes(value):
    return [(value>>(32*i))&MASK for i in range(4)]


def pack(values):
    return sum((x%P)<<(32*i) for i,x in enumerate(values))


def add(a,b):return pack([x+y for x,y in zip(lanes(a),lanes(b))])
def sub(a,b):return pack([x-y for x,y in zip(lanes(a),lanes(b))])


def mul(a,b):
    out=[0]*4
    for i,x in enumerate(lanes(a)):
        for j,y in enumerate(lanes(b)):
            out[(i+j)%4]+=x*y*(3 if i+j>=4 else 1)
    return pack(out)


def inverse(a):
    if not a:raise ValueError('zero inverse')
    exponent=P**4-2
    result=1
    while exponent:
        if exponent&1:result=mul(result,a)
        a=mul(a,a);exponent>>=1
    return result


class Transcript:
    def __init__(self):
        self.digest=kh(b'ziren-koalabear-keccak-terminal-v1')
        self.buffer=bytearray();self.left=0

    def fold(self):
        self.digest=kh(self.digest+self.buffer);self.buffer.clear()

    def observe(self,data):
        self.left=0
        for b in data:
            self.buffer.append(b)
            if len(self.buffer)==100:self.fold()

    def word(self):
        if not self.left:self.fold();self.left=8
        at=4*(8-self.left);self.left-=1
        return int.from_bytes(self.digest[at:at+4],'little')

    def sample(self):
        while True:
            x=self.word()&0x7fffffff
            if x<P:return x

    def extension(self):return pack([self.sample() for _ in range(4)])


def poseidon(values,constants):
    def linear(s):
        v=[]
        for i in range(0,16,4):
            a,b,c,d=s[i:i+4];total=a+b+c+d
            v.extend([total+a+2*b,total+b+2*c,total+c+2*d,total+d+2*a])
        sums=[sum(v[j::4]) for j in range(4)]
        return [(x+sums[i%4])%P for i,x in enumerate(v)]
    diag=[-2,1,2,pow(2,-1,P),3,4,-pow(2,-1,P),-3,-4,pow(256,-1,P),pow(8,-1,P),pow(1<<24,-1,P),-pow(256,-1,P),-pow(8,-1,P),-pow(16,-1,P),-pow(1<<24,-1,P)]
    state=[0]*16
    for at in range(0,len(values),8):
        chunk=values[at:at+8];state[:len(chunk)]=chunk;state=linear(state)
        for r in range(28):
            if r<4 or r>=24:
                state=linear([pow(x+constants[r][i],3,P) for i,x in enumerate(state)])
            else:
                state[0]=pow(state[0]+constants[r][0],3,P);total=sum(state)
                state=[(total+x*d)%P for x,d in zip(state,diag)]
    return state[:8]


class Reference:
    def __init__(self,manifest,packet,output):
        self.manifest=manifest;self.meta=manifest['metadata']
        self.regs=[0]*manifest['registers'];self.t=Transcript();self.output=output
        nf=self.meta['field_count'];nh=self.meta['hash_count']
        assert len(packet)==38+4*nf+32*nh
        self.fields=[int.from_bytes(packet[38+4*i:42+4*i],'little') for i in range(nf)]
        assert all(x<P for x in self.fields)
        self.hashes=[int.from_bytes(packet[38+4*nf+32*i:70+4*nf+32*i],'big') for i in range(nh)]

    def get(self,ref):
        ix=ref&0x0fffffff
        if ref&0x80000000:return ref&0x7fffffff
        if ref&0x40000000:return self.fields[ix]
        if ref&0x20000000:return pack(self.fields[ix:ix+4])
        if ref&0x10000000:return self.hashes[ix]
        return self.regs[ref]

    def run(self,start,end):
        for index,(code,dst,*args) in enumerate(self.manifest['ops'][start:end],start):
            v=None
            if code in (4,5,6,8,20,21,22,23):
                a,b=map(self.get,args)
                if code==4:v=add(a,b)
                elif code==5:v=sub(a,b)
                elif code==6:v=mul(a,b)
                elif code==8:
                    if a!=b:raise ValueError(('assertion',index,a,b))
                elif code==20:v=(a+b)%P
                elif code==21:v=(a-b)%P
                elif code==22:v=a*b%P
                else:v=pack([x*b for x in lanes(a)])
            elif code==7:v=inverse(self.get(args[0]))
            elif code in (10,11,12):
                value=self.get(args[0]);width={10:4,11:16,12:32}[code]
                self.t.observe(value.to_bytes(width,'big' if code==12 else 'little'))
            elif code==13:v=self.t.extension()
            elif code==14:
                bits,ref=args
                if bits:
                    self.t.observe(self.get(ref).to_bytes(4,'little'))
                    assert self.t.word()&((1<<bits)-1)==0,('grind',index)
            elif code==15:v=args[0]
            elif code==16:
                digest=kh(b'ziren-keccak-root-felts-v1'+self.get(args[0]).to_bytes(32,'big'))
                self.regs[dst:dst+8]=[int.from_bytes(digest[i:i+4],'little')%P for i in range(0,32,4)]
            elif code==17:assert self.get(args[0])==self.output[args[1]],('output',index)
            elif code==18:
                first,count,_=args
                self.regs[dst:dst+8]=poseidon(self.fields[first:first+count],self.meta['poseidon_constants'])
            else:raise ValueError(('opcode',code))
            if v is not None:self.regs[dst]=v

    def check(self,context,registers=None):
        size=len(self.regs)*32
        actual=[int.from_bytes(context[i:i+32],'big') for i in range(0,size,32)]
        selected=range(len(self.regs)) if registers is None else registers
        assert all(actual[i]==self.regs[i] for i in selected), next(((i,actual[i],self.regs[i]) for i in selected if actual[i]!=self.regs[i]),None)
        assert context[size:size+32]==self.t.digest,'transcript digest'
        assert int.from_bytes(context[size+32:size+64],'big')==len(self.t.buffer),'buffer length'
        assert int.from_bytes(context[size+64:size+96],'big')==self.t.left,'unread words'
        assert context[size+128:size+128+len(self.t.buffer)]==self.t.buffer,'pending transcript bytes'
        assert context[size+288:size+320]==self.output,'statement changed'
