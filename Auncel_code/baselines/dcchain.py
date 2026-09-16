"""DCchain two-tier coordinator/LinearPBFT flow, executed with threshold BLS.
"""
import hashlib, random
from src.network import encode
from src.nodes import seed_for
from crypto.pvss import Scheme, Element, G1

class ThresholdBLS:
    def __init__(self, nodes, q, seed):
        self.nodes=nodes;self.q=q;self.p=Scheme(rng=random.Random(seed));p=self.p
        coefficients=[p.scalar() for _ in range(q)]
        self.sk=[sum(c*pow(i,j,p.order) for j,c in enumerate(coefficients))%p.order for i in range(1,len(nodes)+1)]
        self.pk=[p.h**p.zr(s) for s in self.sk];self.master=p.h**p.zr(coefficients[0])

    def hashed(self,body):return Element.from_hash(self.p.pairing,G1,hashlib.sha256(encode(body)).digest())
    def sign(self,i,body):return self.hashed(body)**self.p.zr(self.sk[i])
    def verify(self,i,body,sig):return self.p.pairing.apply(sig,self.p.h)==self.p.pairing.apply(self.hashed(body),self.pk[i])
    def combine(self,body,shares):
        if len(shares)<self.q:raise ValueError("insufficient threshold shares")
        ids=list(shares)[:self.q];result=Element.one(self.p.pairing,G1)
        for i in ids:
            weight=1
            for j in ids:
                if j!=i:weight=weight*(-(j+1))*pow(i-j,-1,self.p.order)%self.p.order
            result=result*(shares[i]**self.p.zr(weight))
        if not self.verify_master(body,result):raise ValueError("invalid aggregated BLS certificate")
        return result
    def verify_master(self,body,sig):return self.p.pairing.apply(sig,self.p.h)==self.p.pairing.apply(self.hashed(body),self.master)

class DCchain:
    def __init__(self,consensus,ledger,seed):
        self.consensus=consensus;self.ledger=ledger;self.net=consensus.net;self.seed=seed
        self.local=[ThresholdBLS(nodes,7,seed_for(seed,"dc-local:"+str(s))) for s,nodes in enumerate(consensus.shards)]
        self.coordinators=list(consensus.leaders);self.global_state=dict(ledger.balance)
        self.certificates=[];self.height=0;self.last_trace={}

    def protocol_cpu(self):
        return sum(v for phase,v in self.net.cpu_times.items() if phase.startswith("baseline_") and not phase.endswith("_setup"))

    def vrf_recover(self,shard,tx_id,round_number,excluded):
        """BLS-VRF recovery: unique BLS proof, pairing verification, minimum output."""
        nodes=self.consensus.shards[shard];keys=self.local[shard]
        context=dict(tx=tx_id,shard=shard,view=self.consensus.views[shard]+1,round=round_number)
        candidates=[];pending=[];stage_start=self.net.now
        for index,node in enumerate(nodes):
            if node.id in excluded:continue
            self.net.now=stage_start
            proof=self.net.compute(node.id,"baseline_vrf_generation",keys.sign,index,context)
            arrival=self.net.send(node.id,"DC_RECOVERY:%d"%shard,"DC_VRF_PROOF",dict(context=context,index=index,proof=str(proof)),"cross_shard")
            pending.append((arrival,index,node,proof))
        verify_finishes=[]
        with self.net.service_scope("dc-vrf:%d:%d:proofs"%(shard,round_number),0):
            for arrival,index,node,proof in sorted(pending):
                verifier="DC_VRF_VERIFY:%d:%d"%(shard,index)
                self.net.now=max(float(arrival),self.net.cpu.get(verifier,stage_start))
                valid=self.net.compute(verifier,"baseline_vrf_verification",keys.verify,index,context,proof)
                verify_finishes.append(self.net.now)
                if valid:candidates.append((hashlib.sha256(encode(proof)).digest(),index,node,proof))
        self.net.now=max([stage_start]+verify_finishes)
        self.net.drain()
        if not candidates:return None
        _,index,winner,proof=min(candidates,key=lambda item:item[0])
        recovery_actor="DC_RECOVERY:%d"%shard
        self.net.now=max(self.net.now,self.net.cpu.get(recovery_actor,0.))
        self.net.compute(recovery_actor,"baseline_vrf_processing",lambda:hashlib.sha256(encode((context,index,proof))).digest())
        payload=dict(context=context,winner=winner.id,index=index,proof=str(proof))
        self.net.broadcast("DC_RECOVERY:%d"%shard,[n.id for n in nodes],"DC_VRF_RESULT",payload,"cross_shard")
        verify_start=self.net.now;verify_finishes=[]
        for node in nodes:
            if not node.malicious:
                self.net.now=verify_start
                if not self.net.compute(node.id,"baseline_vrf_verification",keys.verify,index,context,proof):raise AssertionError("invalid VRF recovery proof")
                verify_finishes.append(self.net.now)
        self.net.now=max([verify_start]+verify_finishes)
        self.consensus.views[shard]+=1;self.consensus.leaders[shard]=winner;self.coordinators[shard]=winner
        return winner

    def coordinator(self,shard,tx_id,protocol_start,cpu_start,trace):
        leader=self.coordinators[shard]
        if not leader.malicious:return leader
        delta=self.net.config["network_delay_delta_s"];epsilon=self.net.config["timeout_jitter_epsilon_s"]
        delta_prime=self.protocol_cpu()-cpu_start;t1=delta+delta_prime+epsilon;t2=2*delta+delta_prime+epsilon
        trace.update(delta_s=delta,epsilon_s=epsilon,delta_prime_s=delta_prime,t1_s=t1,t2_s=t2,t1_expired=True,t2_expired=False,view_change=True)
        self.net.now=max(self.net.now,protocol_start+t1)
        self.net.broadcast("DC_TIMEOUT",[n.id for n in self.consensus.shards[shard]],"DC_T1_TIMEOUT",dict(tx=tx_id,shard=shard,T1=t1),"cross_shard")
        recovered=self.vrf_recover(shard,tx_id,1,{leader.id})
        if recovered is not None and not recovered.malicious:return recovered
        trace["t2_expired"]=True;self.net.now=max(self.net.now,protocol_start+t2)
        self.net.broadcast("DC_TIMEOUT",[n.id for n in self.consensus.shards[shard]],"DC_T2_TIMEOUT",dict(tx=tx_id,shard=shard,T2=t2),"cross_shard")
        excluded={leader.id}
        if recovered is not None:excluded.add(recovered.id)
        recovered=self.vrf_recover(shard,tx_id,2,excluded)
        return recovered if recovered is not None and not recovered.malicious else None

    def verify_parallel(self,leader,checks,stage):
        """Run independent global-certificate checks and join at the slowest."""
        start=self.net.now;finishes=[];results={}
        with self.net.service_scope("dc-global:%s:%s"%(leader.id,stage),0):
            for shard,keys,body,certificate in checks:
                worker="DC_GLOBAL_VERIFY:%s:%d"%(leader.id,shard)
                self.net.now=max(start,self.net.cpu.get(worker,start))
                results[shard]=self.net.compute(worker,"baseline_bls_verify",
                    keys.verify_master,body,certificate)
                finishes.append(self.net.now)
        self.net.now=max([start]+finishes)
        return results

    def quorum(self,nodes,keys,leader,body,phase,category,validator=None):
        # Actual signed shares, actual pairing validation, and Lagrange aggregation.
        shares={};pending_shares=[];stage_start=self.net.now
        shard_id=self.net.node_shards.get(str(nodes[0].id),"unknown") if nodes else "unknown"
        with self.net.service_scope("dc:%s:collect"%phase,keys.q,lane=shard_id):
            for i,node in enumerate(nodes):
                self.net.now=stage_start
                if not node.malicious and validator is not None and not self.net.compute(node.id,"baseline_state_verification",validator):continue
                signed_body=body if not node.malicious else dict(body,digest="equivocation")
                sig=self.net.compute(node.id,"baseline_bls_sign",keys.sign,i,signed_body)
                arrival=self.net.send(node.id,leader.id,phase,dict(body=signed_body,share=str(sig),index=i),category)
                pending_shares.append((arrival,i,sig))
            verified_finishes=[];verification_events=[]
            for arrival,i,sig in sorted(pending_shares):
                verifier="DC_BLS_VERIFY:%s:%d"%(leader.id,i)
                self.net.now=max(float(arrival),self.net.cpu.get(verifier,stage_start))
                event_start=len(self.net.service_events)
                valid=self.net.compute(verifier,"baseline_bls_verify",keys.verify,i,body,sig)
                finish=self.net.now
                verification_events.extend(self.net.service_events[event_start:])
                if valid:
                    shares[i]=sig;verified_finishes.append(finish)
            if len(shares)>=keys.q:
                threshold=sorted(verified_finishes)[keys.q-1]
                for event in verification_events:
                    event["background"]=float(event.get("causal_finish_s",0.))>threshold
                self.net.now=max(stage_start,threshold)
                self.net.drain_threshold(verified_finishes,keys.q)
            else:
                self.net.drain()
                self.net.now=max([self.net.now]+[float(event.get("causal_finish_s",0.)) for event in verification_events])
        if len(shares)<keys.q:return None
        with self.net.service_scope("dc:%s:aggregate"%phase,0,lane=shard_id):
            cert=self.net.compute(leader.id,"baseline_bls_aggregate",keys.combine,body,shares)
        qc_ready=self.net.now;event_start=len(self.net.trace_events)
        self.net.broadcast(leader.id,[n.id for n in nodes],phase+"_QC",dict(body=body,certificate=str(cert),signers=[nodes[i].id for i in shares]),category)
        qc_arrivals={event["receiver"]:float(event["delivered"])
                     for event in self.net.trace_events[event_start:]
                     if event.get("kind")==phase+"_QC"}
        qc_broadcast_finish=self.net.now
        qc_finishes=[]
        with self.net.service_scope("dc:%s:qc_verify"%phase,0,lane=shard_id):
            for n in nodes:
                if not n.malicious:
                    self.net.now=max(qc_ready,qc_arrivals.get(str(n.id),qc_ready))
                    if not self.net.compute(n.id,"baseline_bls_verify",keys.verify_master,body,cert):
                        raise AssertionError("invalid aggregate BLS certificate")
                    qc_finishes.append(self.net.now)
        self.net.now=max([qc_broadcast_finish]+qc_finishes)
        self.certificates.append(dict(phase=phase,body=body,certificate=str(cert),signers=[nodes[i].id for i in shares]))
        return cert

    def shard_stage(self,shard,body,proposal=None,proposal_signature=None):
        nodes=self.consensus.shards[shard];leader=self.consensus.leaders[shard]
        if leader.malicious:return None
        self.net.broadcast(leader.id,[n.id for n in nodes],"DC_SHARD_PRE_PREPARE",body,"consensus")
        def validate():
            if body["tx"] not in self.ledger.locked:return False
            if self.ledger.locked[body["tx"]][1]!=body["amount"]:return False
            if proposal is not None and not self.local[shard].verify_master(proposal,proposal_signature):return False
            return True
        proof=None
        for phase in ("DC_SHARD_PREPARE","DC_SHARD_PRECOMMIT","DC_SHARD_COMMIT"):
            signed_body=dict(body,phase=phase)
            proof=self.quorum(nodes,self.local[shard],leader,signed_body,phase,"consensus",validate)
            if proof is None:return None
        return signed_body,proof

    def finalize_epoch(self,epoch_id):
        root=hashlib.sha256(encode(sorted((a,b,v) for (a,b),v in self.global_state.items()))).hexdigest()
        certificates=[];leaders={}
        for shard,nodes in enumerate(self.consensus.shards):
            leader=self.coordinators[shard]
            if leader.malicious:
                protocol_start=self.net.now;cpu_start=self.protocol_cpu()
                trace={"t1_expired":False,"t2_expired":False}
                leader=self.coordinator(shard,"epoch:%d"%int(epoch_id),protocol_start,cpu_start,trace)
                if leader is None or leader.malicious:
                    raise AssertionError("DCchain global confirmation leader recovery failed")
            leaders[shard]=leader
        stage_start=self.net.now;finishes=[]
        for shard,nodes in enumerate(self.consensus.shards):
            self.net.now=stage_start
            leader=leaders[shard]
            body=dict(epoch=int(epoch_id),height=self.height,shard=shard,state_root=root)
            def validate_global():
                current=hashlib.sha256(encode(sorted((a,b,v) for (a,b),v in self.global_state.items()))).hexdigest()
                return current==body["state_root"]
            certificate=self.quorum(nodes,self.local[shard],leader,body,
                                    "DC_GLOBAL_FINALITY","cross_shard",
                                    validate_global)
            if certificate is None:
                raise AssertionError("DCchain global confirmation quorum failed")
            certificates.append(dict(shard=shard,root=root,certificate=str(certificate)))
            finishes.append(self.net.now)
        self.net.now=max([stage_start]+finishes)
        return root,certificates

    def process(self,tx):
        self.height+=1;protocol_start=self.net.now;cpu_start=self.protocol_cpu()
        vrf0={phase:self.net.cpu_times[phase] for phase in ("baseline_vrf_generation","baseline_vrf_verification","baseline_vrf_processing")}
        trace=dict(delta_s=None,epsilon_s=None,delta_prime_s=None,t1_s=None,t2_s=None,t1_expired=False,t2_expired=False,view_change=False,vrf_generation_s=0.,vrf_verification_s=0.,vrf_processing_s=0.)
        if not self.ledger.prepare(tx):return False
        if not tx.cross:
            ok=self.shard_stage(tx.source,dict(tx=tx.id,height=self.height,amount=tx.amount,root=self.ledger.root())) is not None
        else:
            involved=(tx.source,tx.target);leaders={}
            for shard in involved:
                leaders[shard]=self.coordinator(shard,tx.id,protocol_start,cpu_start,trace)
                if leaders[shard] is None:
                    self.ledger.finish(tx,False)
                    for phase,target in (("baseline_vrf_generation","vrf_generation_s"),("baseline_vrf_verification","vrf_verification_s"),("baseline_vrf_processing","vrf_processing_s")):trace[target]=self.net.cpu_times[phase]-vrf0[phase]
                    self.last_trace[tx.id]=trace;return False
            leader=leaders[tx.source]
            global_root=hashlib.sha256(encode(sorted((a,b,v) for (a,b),v in self.global_state.items()))).hexdigest()
            body=dict(tx=tx.id,height=self.height,source=tx.source,target=tx.target,sender=tx.sender,receiver=tx.receiver,amount=tx.amount,asset=tx.asset,state_root=global_root)
            def validate_global():
                computed=hashlib.sha256(encode(sorted((a,b,v) for (a,b),v in self.global_state.items()))).hexdigest()
                return computed==body["state_root"] and self.global_state.get((tx.asset,tx.sender),0)>=tx.amount and body["amount"]==tx.amount and tx.source!=tx.target
            proposals={};proposal_finishes=[];stage_start=self.net.now
            for shard in involved:
                self.net.now=stage_start
                proposal=dict(body,coordinator_shard=shard,phase="DC_PROPOSAL_PROOF")
                self.net.broadcast(leaders[shard].id,[n.id for n in self.consensus.shards[shard]],"DC_PROPOSE",proposal,"cross_shard")
                proof=self.quorum(self.consensus.shards[shard],self.local[shard],leaders[shard],proposal,"DC_PROPOSAL_PROOF","cross_shard",validate_global)
                proposals[shard]=(proposal,proof)
                proposal_finishes.append(self.net.now)
            self.net.now=max([stage_start]+proposal_finishes)
            proposal_checks=[(shard,self.local[shard],proposal,proof)
                             for shard,(proposal,proof) in proposals.items()
                             if proof is not None]
            proposal_valid=self.verify_parallel(leader,proposal_checks,"proposal")
            ok=(len(proposal_checks)==len(involved) and
                all(proposal_valid.get(shard,False) for shard in involved))
            if ok:
                shard_results={};shard_finishes=[];stage_start=self.net.now
                for s in involved:
                    self.net.now=stage_start
                    proposal,proposal_proof=proposals[s]
                    proof=self.shard_stage(s,dict(body,sub_shard=s,proposal_proof=str(proposal_proof)),proposal,proposal_proof)
                    shard_results[s]=proof;shard_finishes.append(self.net.now)
                self.net.now=max([stage_start]+shard_finishes)
                for s in involved:
                    proof=shard_results[s]
                    self.net.send(leaders[s].id,leader.id,"DC_SUBPROPOSAL_RESULT",dict(tx=tx.id,body=proof[0] if proof else None,certificate=str(proof[1]) if proof else None),"cross_shard")
                self.net.drain()
                result_checks=[(s,self.local[s],proof[0],proof[1])
                               for s,proof in shard_results.items()
                               if proof is not None]
                result_valid=self.verify_parallel(leader,result_checks,"subproposal")
                ok=(len(result_checks)==len(involved) and
                    all(result_valid.get(s,False) for s in involved))
            if ok:
                self.net.broadcast(leader.id,[leaders[s].id for s in involved],"DC_STATE_COMMIT",dict(body,verified_commit_shards=list(involved)),"cross_shard")
        def commit_state():
            self.ledger.finish(tx,ok)
            self.global_state=dict(self.ledger.balance)
        if tx.cross:self.net.compute_global(self.consensus.leaders[tx.source].id,"baseline_state_commit",commit_state)
        else:self.net.compute(self.consensus.leaders[tx.source].id,"baseline_state_commit",commit_state)
        nodes=self.coordinators if tx.cross else self.consensus.shards[tx.source]
        body=dict(tx=tx.id,committed=ok,state_root=self.ledger.root());pending_replies=[]
        reply_start=self.net.now
        required=(len(nodes)-1)//3+1;replies=0;valid_reply_finishes=[]
        with self.net.service_scope("dc-reply:%s:sign"%tx.id,required):
            for node in nodes:
                if node.malicious:continue
                self.net.now=reply_start
                sig=self.net.compute(node.id,"baseline_reply_sign",node.sign,encode(body))
                arrival=self.net.send(node.id,tx.sender,"DC_REPLY",body,"cross_shard" if tx.cross else "consensus",sig)
                pending_replies.append((arrival,node,sig))
        verification_events=[]
        with self.net.service_scope("dc-reply:%s:verify"%tx.id,required):
            for arrival,node,sig in sorted(pending_replies,key=lambda item:item[0]):
                verifier="DC_REPLY_VERIFY:%s:%s"%(tx.sender,node.id)
                self.net.now=max(float(arrival),self.net.cpu.get(verifier,reply_start))
                event_start=len(self.net.service_events)
                valid=self.net.compute(verifier,"baseline_reply_verify",node.verify,encode(body),sig)
                verification_events.extend(self.net.service_events[event_start:])
                if valid:
                    replies+=1;valid_reply_finishes.append(self.net.now)
        if replies>=required:
            threshold=sorted(valid_reply_finishes)[required-1]
            for event in verification_events:
                event["background"]=float(event.get("causal_finish_s",0.))>threshold
            self.net.now=max(reply_start,threshold)
            self.net.drain_threshold(valid_reply_finishes,required)
        else:self.net.drain()
        if replies<required:raise AssertionError("insufficient client final replies")
        for phase,target in (("baseline_vrf_generation","vrf_generation_s"),("baseline_vrf_verification","vrf_verification_s"),("baseline_vrf_processing","vrf_processing_s")):
            trace[target]=self.net.cpu_times[phase]-vrf0[phase]
        self.last_trace[tx.id]=trace
        return ok
