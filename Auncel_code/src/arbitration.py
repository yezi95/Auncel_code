
import hashlib, random
from .network import encode
from .nodes import seed_for
from .arbitration_params import arbitration_parameters

def arbitrate(tx,deal,scheme,sk,pk,package,contract,network,seed):
    c=deal["c"];id=deal["id"];mode=tx.fault
    requester=contract.address[tx.sender if mode==1 else tx.receiver]
    committee=contract.arbiters
    _,q,t=arbitration_parameters(network.config,len(committee))
    rng=random.Random(seed_for(seed,"arbitration:"+tx.id))
    active=[];releases=[]
    for i,node in enumerate(committee):
        offline=rng.random()<network.config["arbitrator_offline_probability"]
        dishonest=node.malicious and rng.random()<network.config["arbitrator_byzantine_probability"]
        if offline:continue
        active.append((i,node,not dishonest))
    evidence=b""
    if mode==3:
        network.now=max(network.now,deal["event_due"][1]);deal["delta1_expired"]=True;deal["delta2_expired"]=True;contract.wait_until(deal["due"][1])
        share_arrivals=[];stage_start=network.now
        with network.service_scope("arb3:%s:release"%tx.id,t):
            for i,node,valid in active:
                network.now=stage_start
                share=network.compute(node.id,"pvss_reconstruction",scheme.release,sk[i],package,i+1)
                if not valid:share=(share[0],share[1]**scheme.zr(2))
                arrival=network.send(node.id,requester,"RECONSTRUCTION_SHARE",dict(tx=tx.id,index=share[0],share=str(share[1])),"pvss")
                if valid:share_arrivals.append(arrival)
                releases.append(share)
        network.now=stage_start;network.drain_threshold(share_arrivals,t);good=[]
        verifier_by_index={i:node for i,node,valid in active}
        verification_results=[];verify_stage_start=network.now
        with network.service_scope("arb3:%s:verify"%tx.id,t):
            for share in releases:
                i,value=share
                verifier=verifier_by_index.get(i-1)
                actor=verifier.id if verifier is not None else requester
                network.now=verify_stage_start
                valid=network.compute(actor,"pvss_reconstruction",lambda:scheme.pairing.apply(pk[i-1],value)==scheme.pairing.apply(package["E"][i-1],scheme.h))
                verification_results.append((network.now,bool(valid),share))
        valid_results=sorted((item for item in verification_results if item[1]),key=lambda item:item[0])
        if len(valid_results)>=t:
            network.now=valid_results[t-1][0]
            good=[share for _,_,share in valid_results[:t]]
        else:
            network.now=max((item[0] for item in verification_results),default=verify_stage_start)
            good=[share for _,_,share in valid_results]
        if len(good)<t:
            contract.expire(deal);return False,"insufficient_valid_shares"
        recovered=network.compute(requester,"pvss_reconstruction",scheme.reconstruct,pk,package,good,return_element=True)
        if not network.compute(requester,"pvss_reconstruction",scheme.verify_reconstructed_commitment,package,recovered):
            contract.expire(deal);return False,"reconstructed_commitment_mismatch"
        secret=scheme.pairing.apply(recovered,scheme.h);evidence=str(secret).encode()
    elif mode==2:
        network.now=max(network.now,deal["event_due"][1]);deal["delta1_expired"]=True;deal["delta2_expired"]=True;contract.wait_until(deal["due"][1])
    elif mode==1:
        network.now=max(network.now,deal["event_due"][0]);deal["delta1_expired"]=True;contract.wait_until(deal["due"][0])
    if contract.remaining(deal)<=3*network.config["gssc_block_interval_s"]:
        contract.expire(deal);return False,"request_deadline"
    if not network.compute(requester,"arbitration_evidence_verification",contract.view,c.functions.validEvidence(id,mode,evidence)):
        contract.expire(deal);return False,"invalid_evidence"
    network.broadcast(requester,[n.id for n in committee],"ARBITRATION_REQUEST",dict(tx=tx.id,mode=mode,evidence=evidence.hex()),"arbitration")
    deal["requester"]=requester
    vote_rows=[];stage_start=network.now
    with network.service_scope("arb%d:%s:vote"%(mode,tx.id),q):
        for i,node,valid in active:
            network.now=stage_start
            body=dict(tx=tx.id,mode=mode,support=valid,evidence_hash=contract.w3.keccak(evidence).hex())
            signature=network.compute(node.id,"arbitration_vote_sign",node.sign,encode(body))
            arrival=network.send(node.id,requester,"ARBITRATION_VOTE",body,"arbitration",signature)
            vote_rows.append((arrival,i,node,valid,body,signature))
    valid_arrivals=[row[0] for row in vote_rows if row[3]]
    network.now=stage_start;network.drain_threshold(valid_arrivals,q)
    voters=[];signed_votes=[]
    with network.service_scope("arb%d:%s:vote_verify"%(mode,tx.id),q):
        for arrival,i,node,valid,body,signature in sorted(vote_rows,key=lambda row:row[0]):
            assert network.compute(requester,"arbitration_vote_verify",node.verify,encode(body),signature)
            voters.append((contract.members[i],valid))
            signed_votes.append(dict(member=contract.members[i],body=body,signature=signature.hex()))
            if sum(bool(support) for _,support in voters)>=q:break
    certificate_digest=network.compute(requester,"arbitration_certificate_aggregate",
        lambda: hashlib.sha256(encode(signed_votes)).digest())
    deal["certificate_digest"] = certificate_digest.hex()
    if contract.quorums[tx.asset]!=q:raise AssertionError("arbitration quorum mismatch")
    certificate_ok=contract.cast_votes(deal,voters,mode,evidence)
    if not certificate_ok:
        return False,"certificate_rejected_or_unresolved"
    deal["queued_commit"]=(mode==3 and sum(bool(valid) for _,valid in deal["votes"])>=q)
    if sum(valid for _,valid in deal["votes"])>=q:
        return True,"adjudicated"
    return False,"insufficient_votes"
