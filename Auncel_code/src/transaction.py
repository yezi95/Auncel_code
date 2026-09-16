import csv, hashlib, json, random
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass, asdict, field
from .nodes import seed_for
from .sharding import account_shard

@dataclass
class Transaction:
    id: str
    row: int
    original_hash: str
    block_number: int
    timestamp: int
    asset: str
    sender: str
    receiver: str
    amount: int
    source: int
    target: int
    submitted: float=0.0
    fault: int=0
    state: str="INIT"
    history: list=field(default_factory=list)

    @property
    def cross(self): return self.source!=self.target

    def transition(self, state, at):
        allowed={"INIT":{"SUBMITTED"},"SUBMITTED":{"PREPARED","ABORT"},
                 "PREPARED":{"VERIFIED","ARBITRATION","COMMIT","ABORT"},
                 "VERIFIED":{"ARBITRATION","COMMIT","ABORT"},
                 "ARBITRATION":{"COMMIT","ABORT"}}
        if state not in allowed.get(self.state,set()): raise ValueError((self.id,self.state,state))
        self.state=state; self.history.append([state,at])

def read_dataset(root, settings):
    path=root/settings["path"]
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if digest!=settings["sha256"]: raise ValueError("data.csv SHA256 mismatch: update configuration only after checking source")
    if not settings["mapping_confirmed"]:
        raise ValueError("Confirm columns in configs/system.yaml: currently sender=5, receiver=6, amount=9 (1-based). Then set mapping_confirmed=true.")
    cols=settings["columns"]; rows=[]; excluded={}
    with path.open(encoding="utf-8-sig",newline="") as f:
        if not settings["has_header"]:raise ValueError("The configured XBlock workload must have a header")
        reader=csv.DictReader(f)
        if reader.fieldnames is None or any(name not in reader.fieldnames for name in cols.values()):raise ValueError("XBlock header mismatch: "+str(reader.fieldnames))
        for number,r in enumerate(reader,2):
            try:
                a=Decimal(r[cols["amount"]]);sender=r[cols["sender"]].lower();receiver=r[cols["receiver"]].lower()
                if not a.is_finite() or a!=a.to_integral_value() or not 0<a<2**256:raise ValueError("nonpositive/noninteger/overflow amount")
                if any(len(x)!=42 or not x.startswith("0x") or int(x,16)==0 for x in (sender,receiver)):raise ValueError("nontransfer address")
                if sender==receiver:raise ValueError("self transfer")
                tx_hash=r[cols["hash"]].lower()
                if len(tx_hash)!=66 or not tx_hash.startswith("0x") or int(tx_hash,16)==0:raise ValueError("invalid transaction hash")
                rows.append(dict(row=number,original_hash=tx_hash,block_number=int(r[cols["block"]]),timestamp=int(r[cols["timestamp"]]),asset="ETH",sender=sender,receiver=receiver,amount=int(a)))
            except (IndexError,ValueError,InvalidOperation) as e:
                reason=str(e);excluded[reason]=excluded.get(reason,0)+1
    if not rows:raise ValueError("No eligible original transfers")
    return rows,dict(sha256=digest,eligible=len(rows),excluded=excluded,columns=cols,value_unit=settings["value_unit"],source="XBlock")

def _balanced_real_selection(pools, labels, k, rng):
       buckets={True:{},False:{}}
    for cross,items in pools.items():
        for item in items:
            _,source,target=item
            pair=tuple(sorted((source,target)))
            buckets[cross].setdefault(pair,[]).append(item)
        for items in buckets[cross].values():
            rng.shuffle(items)
    available={cross:{pair:list(items) for pair,items in grouped.items()}
               for cross,grouped in buckets.items()}
    load=[0]*k;selected=[]
    for cross in labels:
        candidates=[pair for pair,items in available[cross].items() if items]
        if not candidates:
            raise ValueError("Insufficient distinct CSV rows for requested cross ratio; no replacement/fabrication allowed")
        scored=[]
        for pair in candidates:
            projected=list(load)
            for shard in set(pair):
                projected[shard]+=1
            mean=sum(projected)/k
            score=(max(projected)-min(projected),
                   max(projected),
                   sum((value-mean)**2 for value in projected),
                   rng.random())
            scored.append((score,pair))
        pair=min(scored,key=lambda item:item[0])[1]
        item=available[cross][pair].pop()
        selected.append(item)
        for shard in set(pair):
            load[shard]+=1
    rng.shuffle(selected)
    return selected,load


def workload(rows,k,alpha,seed,count,rate,dispute_probability):
    pools={False:[],True:[]}
    for row in rows:
        s=account_shard(row["sender"],k,seed);t=account_shard(row["receiver"],k,seed)
        pools[s!=t].append((row,s,t))
    rng=random.Random(seed_for(seed,"workload:"+str(k)+":"+str(alpha)))
    nc=round(count*alpha)
    labels=[True]*nc+[False]*(count-nc)
    selected,load=_balanced_real_selection(pools,labels,k,rng)
    if len(selected)!=count:raise AssertionError("balanced workload size mismatch")
    if sum(int(s!=t) for _,s,t in selected)!=nc:raise AssertionError("cross-shard ratio mismatch")
    txs=[]
    for i,(row,s,t) in enumerate(selected):
        tx=Transaction(id=row["original_hash"],source=s,target=t,submitted=i/rate,**row)
        if tx.cross and rng.random()<dispute_probability:tx.fault=rng.choice([1,2,3])
        txs.append(tx)
    return txs


def latency_workload(rows,k,alpha,seed,count,rate,dispute_probability):
     if not 0 <= float(dispute_probability) <= 1:
        raise ValueError("dispute_probability must be in [0,1]")
    txs=workload(rows,k,alpha,seed,count,rate,0.0)
    cross_indices=[i for i,tx in enumerate(txs) if tx.cross]
    dispute_count=round(len(cross_indices)*float(dispute_probability))
    fault_rng=random.Random(seed_for(seed,"latency_faults:"+str(k)+":"+str(alpha)))
    fault_rng.shuffle(cross_indices)
    selected=cross_indices[:dispute_count]
    base,extra=divmod(dispute_count,3)
    modes=[mode for mode in (1,2,3)
           for _ in range(base+(1 if mode<=extra else 0))]
    fault_rng.shuffle(modes)
    for index,mode in zip(selected,modes):
        txs[index].fault=mode
    if sum(int(tx.fault!=0) for tx in txs)!=dispute_count:
        raise AssertionError("balanced dispute assignment mismatch")
    if selected and len(set(modes))<min(3,dispute_count):
        raise AssertionError("ARB mode assignment mismatch")
    return txs
