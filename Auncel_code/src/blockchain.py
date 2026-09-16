"""PBFT normal path/view change, signed certificates, and conserved account state."""
import hashlib
from collections import defaultdict
from .network import encode

class Ledger:
    def __init__(self,transactions,bond):
        self.balance=defaultdict(int);self.initial=defaultdict(int);self.locked={};self.terminal={};self.blocks=[];self.deferred={}
        for tx in transactions:
            self.balance[(tx.asset,tx.sender)]+=tx.amount+2*bond
            self.balance[(tx.asset,tx.receiver)]+=2*bond
        self.initial.update(self.balance)
        self.native_mode=False;self.nonces=defaultdict(int);self.versions=defaultdict(int);self.native_terms={};self.native_transfers={}

    def prepare(self,tx):
        if tx.id in self.terminal or tx.id in self.locked:return False
        key=(tx.asset,tx.sender)
        if self.balance[key]<tx.amount:return False
        if self.native_mode:
            self.native_terms[tx.id]=(self.nonces[tx.sender],[self.versions[p] for p in (tx.sender,tx.receiver)])
            self.nonces[tx.sender]+=1
        self.balance[key]-=tx.amount;self.locked[tx.id]=(key,tx.amount)
        return True

    def finish(self,tx,commit,defer=False):
        if tx.id in self.terminal:raise ValueError("duplicate finalization")
        if tx.id in self.locked:
            if self.native_mode:
                _,versions=self.native_terms[tx.id]
                if versions!=[self.versions[p] for p in (tx.sender,tx.receiver)]:raise ValueError("stale native state")
                for party in (tx.sender,tx.receiver):self.versions[party]+=1
            key,value=self.locked.pop(tx.id)
            if commit and defer:self.deferred[tx.id]=((tx.asset,tx.receiver),value)
            else:self.balance[(tx.asset,tx.receiver) if commit else key]+=value
        elif commit:raise ValueError("commit without lock")
        self.terminal[tx.id]="COMMIT" if commit else "ABORT"
        if sum(self.balance.values())+sum(v for _,v in self.locked.values())+sum(v for _,v in self.deferred.values())!=sum(self.initial.values()):
            raise AssertionError("ledger conservation")

    def settle_epoch(self):
        for key,value in self.deferred.values():self.balance[key]+=value
        self.deferred.clear()
        assert sum(self.balance.values())==sum(self.initial.values()),"epoch ledger conservation"

    def native_release(self,tx):
        if tx.id in self.terminal or tx.id in self.native_transfers:raise ValueError("replayed release")
        if self.locked.get(tx.id)!=((tx.asset,tx.sender),tx.amount):raise ValueError("native lock mismatch")
        self.native_transfers[tx.id]=self.locked.pop(tx.id)
        return (tx.id,tx.asset,tx.sender,tx.receiver,tx.amount)

    def native_credit(self,tx,commit):
        if tx.id in self.terminal:raise ValueError("replayed credit")
        _,versions=self.native_terms[tx.id]
        if versions!=[self.versions[p] for p in (tx.sender,tx.receiver)]:raise ValueError("stale native credit")
        key,value=self.native_transfers.pop(tx.id)
        self.balance[(tx.asset,tx.receiver) if commit else key]+=value
        for p in (tx.sender,tx.receiver):self.versions[p]+=1
        self.terminal[tx.id]="COMMIT" if commit else "ABORT"
        total=sum(self.balance.values())+sum(v for _,v in self.locked.values())+sum(v for _,v in self.native_transfers.values())
        assert total==sum(self.initial.values()),"native principal conservation"

    def root(self):
        return hashlib.sha256(encode(sorted((a,b,v) for (a,b),v in self.balance.items()))).hexdigest()

class Consensus:
    def __init__(self,shards,network):
        self.shards=shards;self.net=network;self.height=[0]*len(shards)
        self.views=[0]*len(shards);self.logs={n.id:{} for s in shards for n in s}
        self.leaders=[next(n for n in s if n.accounting) for s in shards]
        self.service_cursor=[0]*len(shards)
        self.blocks=[]
        self._verified_batch_blocks={}

    def service_node(self,shard):
        nodes=[n for n in self.shards[shard] if not n.malicious]
        if not nodes:nodes=list(self.shards[shard])
        node=nodes[self.service_cursor[shard]%len(nodes)]
        self.service_cursor[shard]+=1
        return node

    def signed(self,node,payload):
        raw=encode(payload)
        return self.net.compute(node.id,"consensus_sign",node.sign,raw)

    def checked(self,node,payload,sig,verifier):
        return self.net.compute(verifier,"consensus_verify",node.verify,encode(payload),sig)

    def view_change(self,s):
        nodes=self.shards[s];old=self.leaders[s]
        self.net.now+=self.net.config["transaction_deadline_s"]
        for offset in range(1,len(nodes)+1):
            candidate=nodes[(nodes.index(old)+offset)%len(nodes)]
            if candidate.malicious:continue
            self.views[s]+=1;payload=dict(shard=s,view=self.views[s],height=self.height[s],old=old.id,new=candidate.id)
            proof=[]
            for node in nodes:
                if node.malicious:continue
                sig=self.signed(node,payload)
                self.net.send(node.id,candidate.id,"VIEW_CHANGE",payload,"consensus",sig)
                if self.checked(node,payload,sig,candidate.id):proof.append([node.id,sig.hex()])
            self.net.drain()
            if len(proof)<7:continue
            self.net.broadcast(candidate.id,[n.id for n in nodes],"NEW_VIEW",dict(payload=payload,proof=proof),"consensus")
            for node in nodes:
                if not node.malicious:
                    for identity,sig in proof:
                        signer=next(x for x in nodes if x.id==identity)
                        if not self.checked(signer,payload,bytes.fromhex(sig),node.id):raise AssertionError("new view certificate")
            self.leaders[s]=candidate;return candidate
        raise RuntimeError("no live view")

    def verify_certificate(self,certificate,verifier):
        if "block_certificate" in certificate:
            block=certificate["block_certificate"]
            block_id=block.get("block_id")
            cache_key=(str(block_id),int(verifier))
            if cache_key not in self._verified_batch_blocks:
                self._verified_batch_blocks[cache_key]=self.verify_certificate(block,verifier)
            if not self._verified_batch_blocks[cache_key]:return False
            body=block["proposal"]["body"]
            members={entry["tx"] for entry in body.get("entries",[])}
            return certificate.get("entry_tx") in members
        try:
            proposal=certificate["proposal"];s=proposal["shard"]
            if hashlib.sha256(encode(proposal["body"])).hexdigest()!=proposal["digest"]:return False
            body={k:proposal[k] for k in ("shard","height","view","digest")};body["phase"]="COMMIT"
            members={n.id:n for n in self.shards[s]};seen=set()
            for identity,signature in certificate["signatures"]:
                if identity in seen or identity not in members:return False
                if not self.checked(members[identity],body,bytes.fromhex(signature),verifier):return False
                seen.add(identity)
            return len(seen)>=7
        except (KeyError,ValueError,TypeError,IndexError):return False

    def certify_block(self,s,entries,category="consensus"):

        ordered=sorted((dict(entry) for entry in entries),key=lambda item:item["tx"])
        block_id=hashlib.sha256(encode((int(s),ordered))).hexdigest()
        payload=dict(batch=True,block_id=block_id,shard=int(s),entries=ordered)
        certificate=self.certify(s,payload,category=category)
        if certificate is None:return None
        certificate["block_id"]=block_id
        return certificate

    def entry_certificate(self,block_certificate,body,entry_tx):
        proposal=block_certificate["proposal"]
        return dict(
            proposal=dict(shard=proposal["shard"],height=proposal["height"],
                          view=proposal["view"],digest=hashlib.sha256(encode(body)).hexdigest(),
                          body=body),
            signatures=list(block_certificate["signatures"]),
            block_certificate=block_certificate,
            block_id=block_certificate["block_id"],entry_tx=entry_tx,batch=True)

    def verify_block_entry(self,block_certificate,entry_tx,verifier):
        body=block_certificate["proposal"]["body"]
        if entry_tx not in {entry["tx"] for entry in body.get("entries",[])}:return False
        return self.verify_certificate(block_certificate,verifier)

    def certify(self,s,payload,category="consensus",validator=None):
        nodes=self.shards[s];leader=self.leaders[s]
        if leader.malicious:leader=self.view_change(s)
        self.height[s]+=1;h=self.height[s]
        proposal=dict(shard=s,height=h,view=self.views[s],digest=hashlib.sha256(encode(payload)).hexdigest(),body=payload)
        with self.net.service_scope("pbft:%d:%d:preprepare"%(s,h),7):
            sig=self.signed(leader,proposal)
            self.net.broadcast(leader.id,[n.id for n in nodes],"PRE_PREPARE",proposal,category,sig)
            live=[]
            for n in nodes:
                valid=True
                if not n.malicious:
                    if validator is not None:valid=self.net.compute(n.id,"state_verification",validator)
                    if "source_certificate" in payload:
                        valid=valid and self.verify_certificate(payload["source_certificate"],n.id)
                        valid=valid and payload["source_certificate"]["proposal"]["body"]["transaction"]==payload["transaction"]
                if not n.malicious and valid and self.checked(leader,proposal,sig,n.id):
                    self.logs[n.id][h]=dict(digest=proposal["digest"],state="PRE_PREPARED");live.append(n)
        # Every receiving replica verifies distinct voters; no random quorum flag.
        for phase in ("PREPARE","COMMIT"):
            votes=[];body={k:proposal[k] for k in ("shard","height","view","digest")};body["phase"]=phase
            with self.net.service_scope("pbft:%d:%d:%s:sign"%(s,h,phase),7):
                for n in nodes:
                    voted=dict(body)
                    if n.malicious:voted["digest"]="invalid:"+body["digest"]
                    signature=self.signed(n,voted);votes.append((n,voted,signature))
                    for target in live:
                        if target.id!=n.id:self.net.send(n.id,target.id,phase,voted,category,signature)
            self.net.drain();accepted=[]
            for target in live:
                good=[]
                with self.net.service_scope("pbft:%d:%d:%s:verify:%s"%(s,h,phase,target.id),7):
                    for n,voted,signature in votes:
                        self.net.service_background=len(set(good))>=7
                        valid=self.checked(n,voted,signature,target.id)
                        self.net.service_background=False
                        if valid and voted==body:good.append(n.id)
                        if len(set(good))>=7:break
                if len(set(good))>=7:
                    self.logs[target.id][h]["state"]=phase;accepted.append(target)
            live=accepted
            if len(live)<7:return None
        certificate=dict(proposal=proposal,signatures=[[n.id,s.hex()] for n,b,s in votes if b==body])
        self.blocks.append(dict(shard=s,height=h,view=self.views[s],digest=proposal["digest"],certificate=certificate))
        return certificate
