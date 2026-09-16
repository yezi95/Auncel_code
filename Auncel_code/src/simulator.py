import hashlib, json, math, random, time
from collections import defaultdict
from dataclasses import asdict
from Crypto.Signature import eddsa
from .network import Network,encode
from .nodes import seed_for
from .blockchain import Ledger,Consensus
from crypto.pvss import Scheme
from .gssc import GSSC
from .arbitration import arbitrate
from .native_settlement import process as native_process
from .metrics import summary,write_csv,_event_resource
from .arbitration_params import arbitration_parameters
from baselines.dcchain import DCchain


def _parallel_block_pipeline(net, consensus, block_groups, k, seed):
       def run_lane(shard):
        lane=Network(net.config,seed_for(seed,"pbft_block_lane:"+str(shard)),None)
        lane.service_enabled=True;lane.node_shards=dict(net.node_shards)
        local=Consensus(consensus.shards,lane)
        local.height[shard]=consensus.height[shard]
        local.views[shard]=consensus.views[shard]
        local.leaders[shard]=consensus.leaders[shard]
        certificates={}
        slot_durations={}
        slots=sorted(slot for (s,slot) in block_groups if int(s)==int(shard))
        for slot in slots:
            accounting_for=getattr(consensus.shards,"accounting_for",None)
            if accounting_for is not None:
                local.leaders[shard]=accounting_for(shard,slot)
            entries=[{"tx":item.id} for item in block_groups[(shard,slot)]]
            slot_start=lane.now
            certificate=local.certify_block(shard,entries)
            if certificate is None:
                lane.close();raise RuntimeError("shard block consensus could not reach quorum")
            certificates[(int(shard),int(slot))]=certificate
            slot_durations[(int(shard),int(slot))]=max(0.,lane.now-slot_start)
        return shard,lane,local,certificates,slot_durations

      lanes=[run_lane(shard) for shard in range(k)]
    certificates={}
    base=net.now
    net.block_pipeline_shard_duration_s={shard:lane.now for shard,lane,_,_,_ in lanes}
    net.block_pipeline_shard_slot_duration_s={
        key:duration for shard,lane,local,items,slot_durations in lanes
        for key,duration in slot_durations.items()
    }
    net.block_pipeline_parallel=True;net.block_pipeline_lanes=k
    for shard,lane,local,items,slot_durations in sorted(lanes,key=lambda item:item[0]):
        net.merge_parallel_lane(lane,base)
        consensus.height[shard]=local.height[shard]
        consensus.views[shard]=local.views[shard]
        consensus.leaders[shard]=local.leaders[shard]
        consensus.blocks.extend(local.blocks)
        certificates.update(items)
        lane.close()
    return certificates

def run(root,artifact,shards,transactions,config,seed,scheme_name,output,
        capacity_load_mode=None, fixed_capacity_blocks=None):
    output.mkdir(parents=True,exist_ok=True);net=Network(config,seed,output/"messages.jsonl.gz")
    ledger=Ledger(transactions,config["party_bond_wei"]);consensus=Consensus(shards,net)
    net.node_shards={str(n.id):s for s,nodes in enumerate(shards) for n in nodes}
    net.verification_chain_nodes=[n.id for n in getattr(shards,"verification_chain_nodes",[])]
    net.subepoch_accounting={}
    committee=[next(n for n in shard if n.accounting) for shard in shards]
    net.arbitrator_ids={str(n.id) for n in committee}
    start=time.perf_counter();gssc=None;results=[];pvss_setup_s=0
    try:
        if scheme_name=="Auncel":
            ledger.native_mode=True
            setup=time.perf_counter();pvss=Scheme(rng=random.Random(seed_for(seed,"pvss")))
            sk,pk=pvss.keys(len(shards));pvss_setup_s=time.perf_counter()-setup
            _,q,t=arbitration_parameters(config,len(shards))
            gssc=GSSC(artifact,shards,transactions,ledger,config,seed,net,output)
            gssc.consensus=consensus
            net.broadcast("PVSS_SETUP",[n.id for n in committee],"PVSS_PUBLIC_KEYS",dict(parameters=str(pvss.params),keys=[str(x) for x in pk],threshold=t),"pvss")
        else:baseline=DCchain(consensus,ledger,seed)
        runtime_start=time.perf_counter()
        net.init_shard_queues(len(shards),config["shard_block_capacity"],config["shard_block_interval_s"])
             reservations={}
        block_groups=defaultdict(list)
        for scheduled in transactions:
            involved=sorted({int(scheduled.source),int(scheduled.target)})
            slot,block_start=net.schedule_shards(scheduled.id,involved,scheduled.submitted)
            reservations[scheduled.id]=(slot,block_start)
            for shard in involved:block_groups[(shard,slot)].append(scheduled)
        batch_enabled=scheme_name=="Auncel" and config.get("block_consensus_batching",False)
        net.service_enabled=True
              batch_certificates=(_parallel_block_pipeline(net,consensus,block_groups,len(shards),seed)
                            if batch_enabled else {})
        if hasattr(shards,"subepoch_accounting"):
            net.subepoch_accounting={
                "%d:%d" % (int(shard),int(slot)): node.id
                for (shard,slot),node in shards.subepoch_accounting.items()
            }
        def block_certificate(shard,slot):
            return batch_certificates.get((int(shard),int(slot))) if batch_enabled else None
         auncel_worker_cpu=defaultdict(float)
        if scheme_name=="Auncel":
            for event in net.service_events:
                actor=str(event.get("actor") or "")
                if actor in net.node_shards and _event_resource(event,net,"Auncel")=="NODE:"+actor:
                    auncel_worker_cpu[actor]+=float(event.get("cpu_seconds",event.get("seconds",0.)))
        def auncel_service_node(shard):
            nodes=[node for node in consensus.shards[int(shard)] if not node.malicious]
            if not nodes:nodes=list(consensus.shards[int(shard)])
            if not nodes:raise RuntimeError("Auncel shard has no service nodes")
            return min(nodes,key=lambda node:(auncel_worker_cpu[str(node.id)],str(node.id)))
        for index,tx in enumerate(transactions):
            net.service_tx=tx.id
            net.now=max(net.now,tx.submitted)
                  if gssc:
                saved_tx=net.service_tx;net.service_tx=None
                try:gssc.flush_arbitration_proofs()
                finally:net.service_tx=saved_tx
            auncel_event_offset=len(net.service_events)
            admitted=net.now;excluded_before=net.excluded_setup_s;cpu_before=dict(net.cpu_times)
            involved=sorted({int(tx.source),int(tx.target)})
            block_slot,block_start=reservations[tx.id]
            net.now=max(net.now,block_start)
            block_wait=max(0.,net.now-admitted)
            tx.transition("SUBMITTED",tx.submitted)
            before_count=sum(net.protocol_counts.values());before_bytes=sum(net.protocol_sizes.values());gas0=gssc.gas if gssc else 0
            pvss0=sum(v for k,v in net.cpu_times.items() if k.startswith("pvss"))
            key=eddsa.import_private_key(seed_for(seed,"sender:"+tx.sender).to_bytes(32,"big"))
            body=dict(id=tx.id,asset=tx.asset,sender=tx.sender,receiver=tx.receiver,amount=tx.amount,source=tx.source,target=tx.target)
            signature=net.compute(tx.sender,"client_sign",eddsa.new(key,"rfc8032").sign,encode(body))
            leader=consensus.leaders[tx.source]
            worker=(auncel_service_node(tx.source) if scheme_name=="Auncel"
                    else consensus.service_node(tx.source))
            net.send(tx.sender,leader.id,"SUBMIT",body,"cross_shard" if tx.cross else "consensus",signature);net.drain()
            net.compute(worker.id,"client_verify",eddsa.new(key.public_key(),"rfc8032").verify,encode(body),signature)
            tx.transition("PREPARED",net.now);adjudicated=False;trigger=False;reason="normal";deal={}
            dc_trace={}
            if scheme_name=="DCchain":
                commit=baseline.process(tx);dc_trace=baseline.last_trace.get(tx.id,{})
            else:
                source_batch=block_certificate(tx.source,block_slot)
                if not net.compute(worker.id,"native_principal_lock",ledger.prepare,tx):
                    commit=False;reason="insufficient_balance_or_duplicate"
                    ledger.finish(tx,False)
                else:
                    valid_lock=lambda:ledger.locked.get(tx.id)==((tx.asset,tx.sender),tx.amount) and tx.id not in ledger.terminal and tx.amount>0
                    source_payload=dict(transaction=body,locked_amount=ledger.locked[tx.id][1],state_root=ledger.root())
                    if source_batch is not None:
                        if not net.compute(worker.id,"state_verification",valid_lock):
                            cert=None
                        else:
                            cert=consensus.entry_certificate(source_batch,source_payload,tx.id)
                    else:
                        cert=consensus.certify(tx.source,source_payload,validator=valid_lock)
                    if cert is None:
                        commit=False;reason="source_consensus_failed";ledger.finish(tx,False)
                    elif not tx.cross:
                        commit=True;net.compute(worker.id,"native_principal_commit",ledger.finish,tx,True)
                    else:
                        package,secret=net.compute(tx.sender,"pvss_distribution",pvss.distribute,pk,t,tx.id)
                        transcript=json.loads(pvss.serialize(package));verifications=[]
                        net.broadcast(tx.sender,[n.id for n in committee],"PVSS_DISTRIBUTION",transcript,"pvss")
                           if tx.fault==3:
                            valid_count=0;verification_arrivals=[];stage_start=net.now
                            with net.service_scope("pvss:%s:verify"%tx.id,t):
                                for node in committee[:t]:
                                    net.now=stage_start
                                    verified=net.compute(node.id,"pvss_verification",pvss.verify,pk,package)
                                    verifications.append(verified)
                                    if verified:valid_count+=1
                                    arrival=net.send(node.id,tx.sender,"PVSS_VERIFIED",dict(tx=tx.id,valid=verified),"pvss")
                                    if verified:verification_arrivals.append(arrival)
                            net.now=stage_start;net.drain_threshold(verification_arrivals,t)
                            if valid_count<t:raise AssertionError("PVSS threshold not reached")
                         delta_prime_s=sum(v-cpu_before.get(phase,0.)
                                          for phase,v in net.cpu_times.items()
                                          if not phase.endswith("_setup"))
                        deal=gssc.open(tx,str(secret).encode(),delta_prime_s)
                        net.send(tx.sender,tx.receiver,"PVSS_PRIVATE_A",dict(tx=tx.id,a=str(package["a"])),"pvss");net.drain()
                        net.send(consensus.leaders[tx.source].id,consensus.leaders[tx.target].id,"CROSS_PREPARE",dict(transaction=body,source_certificate=cert,commitment=transcript["v"]),"cross_shard");net.drain()
                        target_batch=block_certificate(tx.target,block_slot)
                        target_payload=dict(transaction=body,source_certificate=cert,commitment=transcript["v"])
                        if target_batch is not None:
                            valid_target=lambda:consensus.verify_certificate(cert,worker.id)
                            if not net.compute(worker.id,"state_verification",valid_target):
                                dest=None
                            else:
                                dest=consensus.entry_certificate(target_batch,target_payload,tx.id)
                        else:
                            dest=consensus.certify(tx.target,target_payload)
                        if dest is None:
                            commit=False;reason="destination_consensus_failed"
                            if deal:
                                gssc.expire(deal)
                            ledger.finish(tx,False)
                        else:
                            tx.transition("VERIFIED",net.now)
                            delta_prime_s=sum(v-cpu_before.get(phase,0.) for phase,v in net.cpu_times.items() if not phase.endswith("_setup"))
                            trigger=tx.fault!=0
                            batch_for_tx=({tx.source:source_batch,tx.target:target_batch}
                                          if source_batch is not None and target_batch is not None else None)
                            commit,adjudicated,reason,deal=native_process(
                                tx,package,secret,pvss,sk,pk,gssc,consensus,ledger,
                                delta_prime_s,worker,batch_for_tx,deal,
                                target_prepare_certificate=dest,
                                target_service_node=(auncel_service_node(tx.target)
                                    if scheme_name=="Auncel" else None))
            outcome="COMMIT" if commit else "ABORT"
            final=dict(tx=tx.id,state=outcome,state_root=ledger.root())
            node=consensus.leaders[tx.source]
            signed=net.compute(node.id,"final_sign",node.sign,encode(final))
            deferred=tx.id in ledger.deferred
            net.send(node.id,tx.sender,"COMMIT_ACCEPTED_PENDING_EPOCH" if deferred else "FINAL_CONFIRMATION",final,"cross_shard" if tx.cross else "consensus",signed);net.drain()
            assert net.compute(tx.sender,"final_verify",node.verify,encode(final),signed)
            tx.transition(outcome,net.now)
            timeout_fields={k:(deal.get(k) if tx.cross and scheme_name=="Auncel" else None) for k in ("delta_s","delta_prime_s","epsilon_s","delta1_s","delta2_s","onchain_delta1_s","onchain_delta2_s")}
            timeout_fields.update(dc_trace)
            if batch_enabled:
                slot_consensus=[]
                for s in involved:
                    slot_key=(int(s),int(block_slot))
                    if slot_key not in net.block_pipeline_shard_slot_duration_s:
                        raise RuntimeError("missing per-slot PBFT duration for shard=%d slot=%d" % slot_key)
                               slot_consensus.append(net.block_pipeline_shard_slot_duration_s[slot_key])
            else:
                slot_consensus=[]
            consensus_latency_s=max(slot_consensus,default=0.)
            protocol_latency_s=net.now-admitted-(net.excluded_setup_s-excluded_before)
            results.append(dict(id=tx.id,row=tx.row,asset=tx.asset,sender=tx.sender,receiver=tx.receiver,amount=tx.amount,value_unit="wei",source=tx.source,target=tx.target,cross=tx.cross,fault=tx.fault,state=tx.state,submitted=tx.submitted,confirmed=net.now,admitted=admitted,queueing_delay_s=admitted-tx.submitted,block_slot=block_slot,block_wait_s=block_wait,end_to_end_latency_s=net.now-tx.submitted,excluded_setup_s=net.excluded_setup_s-excluded_before,consensus_latency_s=consensus_latency_s,pvss_latency_s=sum(v-cpu_before.get(phase,0.) for phase,v in net.cpu_times.items() if phase.startswith("pvss")),arbitration_latency_s=sum(v-cpu_before.get(phase,0.) for phase,v in net.cpu_times.items() if phase.startswith("arbitration")),latency_s=protocol_latency_s+consensus_latency_s,protocol_processing_s=sum(v-cpu_before.get(phase,0.) for phase,v in net.cpu_times.items() if not phase.endswith("_setup")),component_service_s=json.dumps({phase:v-cpu_before.get(phase,0.) for phase,v in net.cpu_times.items() if not phase.endswith("_setup")}),arbitration_triggered=trigger,adjudicated=adjudicated,reason=reason,messages=sum(net.protocol_counts.values())-before_count,bytes=sum(net.protocol_sizes.values())-before_bytes,gas=(gssc.gas-gas0 if gssc else 0),pvss_s=sum(v-cpu_before.get(phase,0.) for phase,v in net.cpu_times.items() if phase.startswith("pvss")),history=json.dumps(tx.history),**timeout_fields))
            results[-1]["settlement_pending"]=deferred
            results[-1]["native_settled"]=scheme_name=="Auncel" and tx.cross and tx.id in ledger.terminal
            if scheme_name=="Auncel":
                for event in net.service_events[auncel_event_offset:]:
                    actor=str(event.get("actor") or "")
                    if actor in net.node_shards and _event_resource(event,net,"Auncel")=="NODE:"+actor:
                        auncel_worker_cpu[actor]+=float(event.get("cpu_seconds",event.get("seconds",0.)))
            if gssc:gssc.flush_arbitration_proofs()
            if (index+1)%50==0:
                print(scheme_name,"seed",seed,"transactions",index+1,"/",len(transactions),flush=True)
        assert not ledger.locked
        epoch_start=net.now
        net.service_tx=None
        net.service_epoch=True
        dcchain_epoch_root=None;dcchain_epoch_certificates=[]
        dcchain_epoch_finality_start=epoch_start
        dcchain_epoch_finality_finish=epoch_start
        if scheme_name=="DCchain":
            dcchain_epoch_root,dcchain_epoch_certificates=baseline.finalize_epoch(seed)
            dcchain_epoch_finality_finish=net.now
        if gssc:gssc.flush_arbitration_proofs(force=True)
        epoch_roots=gssc.finalize_epochs() if gssc else {}
        if gssc:
            for asset,root in epoch_roots.items():
                if consensus.certify(0,dict(epoch=gssc.epoch_id,asset=asset,ait_merkle_root=root,finalized_transactions=sum(t["cross"] for t in results))) is None:raise AssertionError("verification block root consensus")
        net.service_epoch=False
        epoch_finality_finish=net.now
        result=summary(results,net,time.perf_counter()-runtime_start,gssc.gas if gssc else 0,
                       epoch_service_s=epoch_finality_finish-epoch_start,
                       epoch_finality_start_s=epoch_start,
                       epoch_finality_finish_s=epoch_finality_finish,
                       dcchain_finality_start_s=dcchain_epoch_finality_start,
                       dcchain_finality_finish_s=dcchain_epoch_finality_finish,
                       scheme=scheme_name,k=len(shards),
                       capacity_load_mode=capacity_load_mode,
                       fixed_capacity_blocks=fixed_capacity_blocks)
        result.update(block_consensus_batching=batch_enabled,
                      block_pipeline_parallel=bool(batch_enabled),
                      block_pipeline_lanes=(len(shards) if batch_enabled else 0),
                      verification_chain_nodes=list(net.verification_chain_nodes),
                      subepoch_accounting=dict(net.subepoch_accounting),
                      certified_block_count=len(batch_certificates),
                      certified_block_entries=sum(len(v) for v in block_groups.values()) if batch_enabled else 0,
                      dcchain_global_finality_root=dcchain_epoch_root,
                      dcchain_global_finality_shards=len(dcchain_epoch_certificates),
                      consensus_batch_policy=("one PBFT certificate per shard block; per-transaction state checks retained"
                                              if batch_enabled else "one PBFT certificate per transaction"))
        if gssc:
            assert not ledger.locked and not ledger.deferred and not ledger.native_transfers
            assert sum(ledger.balance.values())==sum(ledger.initial.values())
            normal_ids={t["id"] for t in results if t["cross"] and not t["arbitration_triggered"]}
            normal_gssc_writes=[c for c in net.gssc_services if c["tx"] in normal_ids]
            result.update(principal_model="shard-native; GSSC state and collateral",
                          normal_path_gssc_writes=len(normal_gssc_writes),
                       epoch_role="verification-chain checkpoint after shard finality; GSSC transaction state and AIT are finalized",
                normal_native_completion_latency_s=(sum(t["latency_s"] for t in results if t["id"] in normal_ids)/len(normal_ids) if normal_ids else None))
            (output/"native_ait.json").write_text(json.dumps(gssc.local_records,default=lambda v:v.hex() if isinstance(v,bytes) else str(v),indent=2),encoding="utf-8")
        costs=gssc.cost_records if gssc else [];valid_costs=[r for r in costs if r["valid"]];invalid_costs=[r for r in costs if not r["valid"]]
        timeout_rows=[t for t in results if t["delta1_s"] is not None]
        result.update(setup_wall_s=runtime_start-start,pvss_setup_s=pvss_setup_s,contract_setup_gas=gssc.setup_gas if gssc else 0,
            gas_cost_wei=config.get("gas_cost_wei"),request_bond_wei=config.get("request_bond_wei"),
            arbiter_bond_wei=config.get("arbiter_bond_wei"),
            minimum_arbitration_reward_wei=config.get("minimum_arbitration_reward_wei"),
            delta_s=config["network_delay_delta_s"],epsilon_s=config["timeout_jitter_epsilon_s"],delta_prime_s_mean=(sum(t["delta_prime_s"] for t in timeout_rows)/len(timeout_rows) if timeout_rows else None),
            delta1_s_mean=(sum(t["delta1_s"] for t in timeout_rows)/len(timeout_rows) if timeout_rows else None),delta2_s_mean=(sum(t["delta2_s"] for t in timeout_rows)/len(timeout_rows) if timeout_rows else None),epoch_roots=json.dumps(epoch_roots),
            valid_arbitration_requests=len(valid_costs),invalid_arbitration_requests=len(invalid_costs),
             gssc_arbitration_batch_calls=(gssc.arbitration_batch_calls if gssc else 0),
             gssc_arbitration_batched_proofs=(gssc.arbitration_batched_proofs if gssc else 0),
             gssc_arbitration_batch_fallbacks=(gssc.arbitration_batch_fallbacks if gssc else 0),
            cost_amplification_experiment="disabled_in_normal_workload",
            cost_amplification_ratio_valid=(sum(r["cost_amplification_ratio"] for r in valid_costs)/len(valid_costs) if valid_costs else None),
            cost_amplification_ratio_invalid=(sum(r["cost_amplification_ratio"] for r in invalid_costs)/len(invalid_costs) if invalid_costs else None))
        write_csv(output/"transactions.csv",results)
        write_csv(output/"resource_service_events.csv",net.service_events)
        write_csv(output/"gssc_service_calls.csv",net.gssc_services)
        (output/"service_accounting.json").write_text(json.dumps(result["service_accounting"],indent=2),encoding="utf-8")
        write_csv(output/"final_balances.csv",[dict(asset=a,address=b,initial=ledger.initial[(a,b)],final=v) for (a,b),v in sorted(ledger.balance.items())])
        (output/"blocks.json").write_text(json.dumps(consensus.blocks),encoding="utf-8")
        if scheme_name=="DCchain":(output/"dc_certificates.json").write_text(json.dumps(baseline.certificates),encoding="utf-8")
        (output/"summary.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
        return result
    finally:
        net.close()
        if gssc:gssc.close()
