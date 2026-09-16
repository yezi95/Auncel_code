import json
from Crypto.Signature import eddsa
from eth_abi import encode as abi_encode
from .network import encode
from .arbitration import arbitrate
from .nodes import seed_for


def process(tx, package, secret, pvss, sk, pk, gssc, consensus, ledger, delta_prime,
            worker=None, batch_certificates=None, deal=None,
            target_prepare_certificate=None, target_service_node=None):
    net=consensus.net
    source_worker=worker or consensus.service_node(tx.source)
    target_worker=target_service_node or consensus.service_node(tx.target)
    if not hasattr(gssc,"native_ids"):gssc.native_ids=set()
    nonce,versions=ledger.native_terms[tx.id]
    native_id=net.compute(source_worker.id,"native_txid",gssc.w3.solidity_keccak,
        ["address","address","uint256","uint256","bytes32"],
        [gssc.w3.to_checksum_address(tx.sender),gssc.w3.to_checksum_address(tx.receiver),nonce,gssc.epoch_id,bytes.fromhex(tx.original_hash[2:])])
    if bytes(native_id) in gssc.native_ids:raise AssertionError("native transaction replay")
    gssc.native_ids.add(bytes(native_id))
    delta=net.config["network_delay_delta_s"];epsilon=net.config["timeout_jitter_epsilon_s"]
    start=net.now

    if deal is None:
        deal=dict(delta_s=delta,epsilon_s=epsilon,delta_prime_s=delta_prime,
            delta1_s=delta+delta_prime+epsilon,delta2_s=2*delta+delta_prime+epsilon,
            onchain_delta1_s=None,onchain_delta2_s=None)
    adjudicated=False;reason="normal";commit=True
    response_certificate=None
    ack=None
    ack_signature=None
    receiver_key=None

    onchain_clock_s=0.0
    delta2_start=None
    if tx.fault!=1:
        if target_prepare_certificate is None:
            raise RuntimeError("receiver response requires a certified target-shard prepare")
        response=dict(tx=native_id.hex(),nonce=nonce,versions=versions,epoch=gssc.epoch_id,
                      sender=tx.sender,receiver=tx.receiver)
        response_payload=dict(kind="receiver_response",transaction=tx.id,
            native_id=native_id.hex(),nonce=nonce,versions=versions,epoch=gssc.epoch_id,
            prepare_digest=target_prepare_certificate["proposal"]["digest"])

        def valid_response():
            verifier=net.compute_actors[-1]
            prepare_body=target_prepare_certificate["proposal"]["body"]
            prepared=prepare_body.get("transaction",{})
            if prepared.get("id")!=tx.id:
                return False
            if int(target_prepare_certificate["proposal"]["shard"])!=int(tx.target):
                return False
            return consensus.verify_certificate(target_prepare_certificate,verifier)

        response_certificate=consensus.certify(tx.target,response_payload,
                                                validator=valid_response)
        if response_certificate is None:
            raise RuntimeError("receiver response could not reach target-shard quorum")
        net.send(tx.receiver,tx.sender,"RECEIVER_RESPONSE",
                 dict(response=response,certificate=response_certificate),"cross_shard")
        net.drain()
        if deal:
            event_base=deal.get("event_base_s",start)
            measured_processing=max(float(deal.get("delta_prime_s",0.)),
                                    float(delta_prime),net.now-event_base)
            deal["delta_prime_s"]=measured_processing
            deal["delta1_s"]=delta+measured_processing+epsilon
            deal["delta2_s"]=2*delta+measured_processing+epsilon
            deal["event_due"]=[event_base+deal["delta1_s"],
                               event_base+deal["delta2_s"]]
            if net.now>start+deal["delta1_s"]:
                raise RuntimeError("receiver response exceeded Delta1")
            delta2_start=net.now
            call_start=net.now
            gssc.call(deal["c"],"respond",gssc.address[tx.receiver],deal["id"])
            onchain_clock_s+=net.now-call_start
    if tx.fault==0:
        net.send(tx.sender,tx.receiver,"SECRET_RELEASE",dict(response,secret=str(secret)),"cross_shard");net.drain()
        if deal and net.now-onchain_clock_s>delta2_start+deal["delta2_s"]:raise RuntimeError("normal secret release exceeded Delta2")

        receiver_key=eddsa.import_private_key(seed_for(gssc.epoch_id,"sender:"+tx.receiver).to_bytes(32,"big"))
        ack=encode(dict(response,secret_hash=gssc.w3.keccak(str(secret).encode()).hex(),accepted=True))
        ack_signature=net.compute(tx.receiver,"native_receiver_ack_sign",eddsa.new(receiver_key,"rfc8032").sign,ack)
        net.broadcast(tx.receiver,[n.id for shard in (tx.source,tx.target) for n in consensus.shards[shard]],
            "NATIVE_RECEIVER_ACCEPT",dict(ack=ack.hex(),signature=ack_signature.hex()),"cross_shard")

        eddsa.new(receiver_key.public_key(),"rfc8032").verify(ack,ack_signature)
        if deal:
            gssc.call(deal["c"],"completeNormal",gssc.address[tx.sender],deal["id"],str(secret).encode())
            gssc.finish_audit(deal,False)
    else:
        tx.transition("ARBITRATION",net.now)

        if deal is None:
            deal=gssc.open(tx,str(secret).encode(),delta_prime)
        c=deal["c"];id=deal["id"]
        if tx.fault==2:
            invalid=secret**pvss.zr(2)
            net.send(tx.sender,tx.receiver,"INVALID_SECRET_RELEASE",dict(tx=native_id.hex(),secret=str(invalid)),"cross_shard");net.drain()

            gssc.call(c,"publishSecret",gssc.address[tx.sender],id,str(invalid).encode())
        adjudicated,reason=arbitrate(tx,deal,pvss,sk,pk,package,gssc,net,gssc.epoch_id)
        commit=gssc.finish_audit(deal,adjudicated)
    def record():
        entries=[]
        for account,action in ((tx.sender,"DEBIT_COMMIT" if commit else "REFUND_ABORT"),(tx.receiver,"CREDIT_COMMIT" if commit else "NO_CREDIT_ABORT")):
            action_hash=gssc.w3.keccak(text=action)

            key=gssc.w3.keccak(abi_encode(["uint256","bytes32","address"],[gssc.epoch_id,native_id,account]))
            value=gssc.w3.keccak(abi_encode(["bytes32"],[action_hash]))
            entries.append((key,value))
        return entries
    entries=net.compute(source_worker.id,"native_ait_record",record)
    decision=dict(tx=tx.id,native_id=native_id.hex(),nonce=nonce,versions=versions,
        sender=tx.sender,receiver=tx.receiver,ait=[(key.hex(),value.hex()) for key,value in entries],
        epoch=gssc.epoch_id,source=tx.source,target=tx.target,amount=tx.amount,commit=commit)
    if tx.fault==0:
        decision.update(receiver_ack=ack.hex(),receiver_signature=ack_signature.hex(),
                        receiver_response_certificate=response_certificate)
    else:decision.update(dispute_id=deal["id"].hex(),dispute_contract=deal["c"].address)
    def valid():
        if ledger.locked.get(tx.id)!=((tx.asset,tx.sender),tx.amount):return False
        if versions!=[ledger.versions[p] for p in (tx.sender,tx.receiver)]:return False
        if tx.fault:
            expected=2 if commit else 3

            if deal.get("proof_queued",False):
                return (gssc.cached_deal_state(tx.asset,deal["id"])==1 and
                        deal.get("queued_commit")==commit)
            state=gssc.view(deal["c"].functions.transactionState(deal["id"]))
            return state==expected
        if response_certificate is None:
            return False
        response_body=response_certificate["proposal"]["body"]
        if (response_body.get("kind")!="receiver_response" or
                response_body.get("transaction")!=tx.id or
                response_body.get("native_id")!=native_id.hex()):
            return False
        if not consensus.verify_certificate(response_certificate,net.compute_actors[-1]):
            return False
        try:
            eddsa.new(receiver_key.public_key(),"rfc8032").verify(ack,ack_signature)
            return True
        except ValueError:return False
    certificates=[]
    for shard in (tx.source,tx.target):
        batch_certificate=(batch_certificates or {}).get(shard)
        if batch_certificate is not None:

            net.broadcast(consensus.leaders[tx.source].id,[n.id for n in consensus.shards[shard]],"NATIVE_DECISION",decision,"cross_shard")
            if not consensus.verify_block_entry(batch_certificate,tx.id,source_worker.id):
                raise RuntimeError("transaction is not in the certified shard block")
            if not net.compute(source_worker.id,"state_verification",valid):
                raise RuntimeError("native decision state validation failed")
            cert=consensus.entry_certificate(batch_certificate,decision,tx.id)
        else:
            net.broadcast(consensus.leaders[tx.source].id,[n.id for n in consensus.shards[shard]],"NATIVE_DECISION",decision,"cross_shard")
            cert=consensus.certify(shard,decision,validator=valid)
            if cert is None:raise RuntimeError("native decision could not reach shard quorum")
        certificates.append(cert)

    before={p:ledger.balance[(tx.asset,p)] for p in (tx.sender,tx.receiver)}
    source=source_worker;recipient=target_worker if commit else source_worker
    receipt=net.compute(source_worker.id,"native_principal_release",ledger.native_release,tx)
    receipt_body=encode(dict(receipt=receipt,commit=commit,native_id=native_id.hex()))
    receipt_sig=net.compute(source.id,"native_release_sign",source.sign,receipt_body)
    net.send(source.id,recipient.id,"NATIVE_PRINCIPAL_RELEASE",dict(body=receipt_body.hex()),"cross_shard",receipt_sig);net.drain()
    assert net.compute(recipient.id,"native_release_verify",source.verify,receipt_body,receipt_sig)
    credit_worker=target_worker if commit else source_worker
    net.compute(credit_worker.id,"native_principal_credit",ledger.native_credit,tx,commit)
    expected=dict(before)
    expected[tx.receiver if commit else tx.sender]+=tx.amount
    assert all(ledger.balance[(tx.asset,p)]==v for p,v in expected.items()),"native balance delta"
    gssc.audit.write(json.dumps(dict(transaction=tx.id,stage="native_principal",native_id=native_id.hex(),
        commit=commit,before=before,after=expected,locked_principal=tx.amount,passed=True))+"\n")
    gssc.local_records.append(dict(asset=tx.asset,tx=tx.id,shards=(tx.source,tx.target),entries=entries,certificates=certificates))
    if tx.fault==0 and deal:
        state=gssc.view(deal["c"].functions.transactionState(deal["id"]))
        if state!=2:
            raise RuntimeError("normal GSSC transaction did not reach Committed")
    return commit,adjudicated,reason,deal
