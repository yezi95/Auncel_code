"""Pairing operations use PYPBC."""
import sys, hashlib, secrets
from pathlib import Path
from pypbc import Parameters, Pairing, Element, G1, GT, Zr

class Scheme:
    def __init__(self,parameter_file=None,rng=None):
        self.rng=rng
        parameter_file=Path(parameter_file or Path(__file__).parent/'pbc.params')
        if parameter_file.exists():self.params=Parameters(param_string=parameter_file.read_text())
        else:
            self.params=Parameters(qbits=512,rbits=160)
            parameter_file.write_text(str(self.params))
        self.pairing=Pairing(self.params)
        self.order=int(next(line.split()[1] for line in str(self.params).splitlines() if line.startswith('r ')))
        self.g=Element.from_hash(self.pairing,G1,hashlib.sha256(b'Auncel:g:v1').digest())
        self.h=Element.from_hash(self.pairing,G1,hashlib.sha256(b'Auncel:h:v1').digest())
        self.base=self.pairing.apply(self.h,self.h)
    def zr(self,x):return Element(self.pairing,Zr,value=int(x)%self.order)
    def scalar(self):return self.randbelow(self.order-1)+1
    def randbelow(self,n):return self.rng.randrange(n) if self.rng is not None else secrets.randbelow(n)
    def keys(self,n):
        sk=[self.scalar() for _ in range(n)]
        return sk,[self.h**self.zr(x) for x in sk]
    def distribute(self,pk,t,context):
        if not 1<=t<=len(pk):raise ValueError('threshold')
        a=self.scalar();coeff=[self.scalar() for _ in range(t)]
        shares=[sum(c*pow(i,j,self.order) for j,c in enumerate(coeff))%self.order for i in range(1,len(pk)+1)]
        secret=self.base**self.zr(coeff[0])
        package={'t':t,'context':context,'v':secret**self.zr(a),'a':a,
                 'V':[self.g**self.zr(s) for s in shares],
                 'E':[key**self.zr(s) for key,s in zip(pk,shares)]}
        return package,secret
    def interpolate_commitment(self,p):
        ids=list(range(1,p['t']+1));value=Element.one(self.pairing,G1)
        for i in ids:
            w=1
            for j in ids:
                if i!=j:w=w*(-j)*pow(i-j,-1,self.order)%self.order
            value=value*(p['V'][i-1]**self.zr(w))
        return value
    def verify(self,pk,p,dual_mode='random'):
        n=len(pk);t=p['t']
        if not 1<=t<=n or len(p['V'])!=n or len(p['E'])!=n:return False
          for key,v,e in zip(pk,p['V'],p['E']):
            if self.pairing.apply(key,v)!=self.pairing.apply(e,self.g):return False
         weights=[]
        for i in range(1,n+1):
            denominator=1
            for j in range(1,n+1):
                if i!=j:denominator=denominator*(i-j)%self.order
            weights.append(pow(denominator,-1,self.order))
        if dual_mode=='random' and n>t:
           coeff=[self.randbelow(self.order) for _ in range(n-t)]
            product=Element.one(self.pairing,G1)
            for i,(v,w) in enumerate(zip(p['V'],weights),1):
                value=sum(c*pow(i,k,self.order) for k,c in enumerate(coeff))%self.order
                product=product*(v**self.zr(w*value))
            return product==Element.one(self.pairing,G1)
        for k in range(n-t):
            product=Element.one(self.pairing,G1)
            for i,(v,w) in enumerate(zip(p['V'],weights),1):product=product*(v**self.zr(w*pow(i,k,self.order)))
            if product!=Element.one(self.pairing,G1):return False
        return True
    def release(self,sk,p,i):
        return i,p['E'][i-1]**self.zr(pow(sk,-1,self.order))
    def reconstruct(self,pk,p,releases,return_element=False):
        shares={}
        for i,d in releases:
            if i in shares or not 1<=i<=len(pk):raise ValueError('duplicate or invalid index')
            if self.pairing.apply(pk[i-1],d)!=self.pairing.apply(p['E'][i-1],self.h):raise ValueError('invalid released share')
            shares[i]=d
        if len(shares)<p['t']:raise ValueError('insufficient shares')
        ids=list(shares)[:p['t']];r=Element.one(self.pairing,G1)
        for i in ids:
            w=1
            for j in ids:
                if i!=j:w=w*(-j)*pow(i-j,-1,self.order)%self.order
            r=r*(shares[i]**self.zr(w))
        return r if return_element else self.pairing.apply(r,self.h)
    def verify_reconstructed_commitment(self,p,D):
        if self.pairing.apply(self.g,D)!=self.pairing.apply(self.interpolate_commitment(p),self.h):return False
        return self.verify_secret(p,self.pairing.apply(D,self.h))
    def verify_secret(self,p,S):return S**self.zr(p['a'])==p['v']
    def serialize(self,p):
        import json
       return json.dumps({k:([str(z) for z in v] if isinstance(v,(list,tuple)) else str(v)) for k,v in p.items() if k!='a'},sort_keys=True).encode()
