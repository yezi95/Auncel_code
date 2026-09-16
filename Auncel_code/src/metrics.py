import csv, json, math
from collections import defaultdict
import numpy as np
from .arbitration_params import arbitration_parameters

DEDICATED_VERIFIER_PHASES=frozenset({
    "consensus_sign", "consensus_verify",
    "pvss_distribution", "pvss_verification", "pvss_secret_verification",
    "pvss_reconstruction", "evm_view_cpu",
    "epoch_state_verification", "epoch_certificate_sign",
    "ait_merkle_build", "epoch_digest",
})

def _is_arbitration_phase(phase):
    return phase.startswith("arbitration_") or phase=="pvss_reconstruction"

def _message_tx_id(event):
    payload=event.get("payload")
    if isinstance(payload,dict):
        if payload.get("tx") is not None:return str(payload["tx"])
        transaction=payload.get("transaction")
        if isinstance(transaction,dict) and transaction.get("id") is not None:
            return str(transaction["id"])
    return str(event.get("tx")) if event.get("tx") is not None else None

def write_csv(path,rows):
    rows=list(rows);path.parent.mkdir(parents=True,exist_ok=True)
    if not rows:return
    with path.open("w",encoding="utf-8",newline="") as f:
        fields=list(dict.fromkeys(k for row in rows for k in row))
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)

def _event_resource(event,network,scheme=None):
     raw=str(event.get("resource") or event.get("actor"))
    actor=str(event.get("actor") or raw)
    phase=str(event.get("phase") or "")
    if raw in ("GSSC","DC_GLOBAL"):
        return raw
    if phase.startswith("arbitration_") or phase=="pvss_reconstruction":
        if actor in getattr(network,"arbitrator_ids",set()):
            return "ARBITRATOR:"+actor
        return "ARBITRATION_AGGREGATOR:"+actor
    if phase.startswith("baseline_") or phase in DEDICATED_VERIFIER_PHASES:
        if actor in network.node_shards:
            return ("VERIFIER:" if scheme=="Auncel" else "NODE:")+actor
        return "VERIFIER:"+actor
    if actor in network.node_shards:
        if scheme=="Auncel":
         return "NODE:"+actor
         return "SHARD:"+str(network.node_shards[actor])
    return "ACTOR:"+actor

def _event_resources(event,network,scheme=None):
    resources=event.get("resources")
    if resources:
        return list(dict.fromkeys(str(resource) for resource in resources))
    return [_event_resource(event,network,scheme)]

def _stage_quorum(group,k,config=None):
    phase=str(group[0].get("phase") or "")
    explicit=group[0].get("group_quorum")
    if explicit not in (None,""):
        try:
            explicit=int(explicit)
            return None if explicit<=0 else max(1,explicit)
        except (TypeError,ValueError):pass
    fanout={"consensus_sign","consensus_verify","pvss_verification",
            "pvss_reconstruction","arbitration_vote_sign",
            "arbitration_certificate_sign","baseline_bls_sign",
            "baseline_bls_verify"}
    if phase not in fanout:return None
    if phase.startswith("pvss") or phase.startswith("arbitration_"):
        if config is not None:
            return arbitration_parameters(config,int(k))[1]
        return max(1,2*(int(k)-1)//3+2)
    if phase.startswith("baseline_") or phase.startswith("consensus_"):
        return 7
    return None

def resource_timeline(transactions,network,k,scheme=None,capacity_load_mode=None,
                      fixed_capacity_blocks=None):
    capacity=int(network.config["shard_block_capacity"])
    interval=float(network.config["shard_block_interval_s"])
    if capacity<=0 or interval<=0:raise ValueError("invalid block capacity/interval")
    if fixed_capacity_blocks is not None:
        try:fixed_capacity_blocks=int(fixed_capacity_blocks)
        except (TypeError,ValueError):
            raise ValueError("fixed_capacity_blocks must be a positive integer")
        if fixed_capacity_blocks<=0:
            raise ValueError("fixed_capacity_blocks must be a positive integer")
    tx_by_id={str(tx["id"]):tx for tx in transactions}
    slots=[defaultdict(int) for _ in range(k)]
    releases={};slot_records={}
    for tx in transactions:
        involved=sorted({int(tx["source"]),int(tx["target"])})
        recorded=getattr(network,"shard_block_assignments",{}).get(tx["id"])
        if recorded is not None:
            slot=int(recorded["slot"])
            if recorded.get("shards")!=involved:raise ValueError("shard reservation mismatch")
        else:
            slot=0
            while any(slots[s][slot]>=capacity for s in involved):slot+=1
        for s in involved:slots[s][slot]+=1
        releases[str(tx["id"])]=float(tx.get("submitted",0.))
        slot_records[str(tx["id"])]=dict(shards=involved,slot=slot,
            service_release_s=slot*interval,
            admission_release_s=float(tx.get("submitted",0.)))

    available=defaultdict(float)
    causal=defaultdict(float);wall_work=defaultdict(float)
    active_work=defaultdict(float);active_wall=defaultdict(float)
    background_work=defaultdict(float);dedicated_work=defaultdict(float)
    arbitration_work=defaultdict(float);transaction_ends=defaultdict(float)
    transaction_resource_finishes=defaultdict(list)
    block_shard_ready=[0.0]*k;block_slot_ready=defaultdict(float);pre_active_work=defaultdict(float);normal_pre_active_work=defaultdict(float);normal_pbft_slot_node_work=defaultdict(float)
    normal_slots={(int(t["source"]),int(slot_records[str(t["id"])] ["slot"])) for t in transactions
        if not t.get("arbitration_triggered",False)}
    normal_slots.update((int(t["target"]),int(slot_records[str(t["id"])] ["slot"])) for t in transactions
        if not t.get("arbitration_triggered",False))
    grouped=[];current_key=None;current_group=[];scoped_group_indices={}
    def flush_group():
        nonlocal current_key,current_group
        if current_group:grouped.append(current_group)
        current_key=None;current_group=[]
    for event in network.service_events:
        tx_id=event.get("tx")
        stream="__global__" if tx_id is None else str(tx_id)
        group_name=str(event.get("group") or "")
        key=(stream,group_name,str(event.get("phase") or ""))
        if group_name:
             flush_group()
            index=scoped_group_indices.get(key)
            if index is None:
                scoped_group_indices[key]=len(grouped)
                grouped.append([event])
            else:
                grouped[index].append(event)
            continue
        if not current_group or key!=current_key:
            flush_group();current_key=key;current_group=[event]
        else:current_group.append(event)
    flush_group()

    tx_groups=defaultdict(list)
    for group in grouped:
        tx_id=group[0].get("tx")
        if tx_id is None:tx_groups["__global__"].append(group)
        else:tx_groups[str(tx_id)].append(group)


    global_groups=tx_groups.get("__global__",[])
    pre_groups=[g for g in global_groups if not any(e.get("epoch_finalization") for e in g)]
    post_groups=[g for g in global_groups if any(e.get("epoch_finalization") for e in g)]
    for group in pre_groups:
        for event in group:
            resources=_event_resources(event,network,scheme)
            cost=float(event.get("cpu_seconds",event.get("seconds",0.)))
            wall=float(event.get("seconds",0.))
            if not math.isfinite(cost) or cost<0 or not math.isfinite(wall) or wall<0:
                raise ValueError("invalid measured service")
            start=max(available[resource] for resource in resources);finish=start+cost
            for resource in resources:
                available[resource]=finish
                pre_active_work[resource]+=cost
                active_work[resource]+=cost;active_wall[resource]+=wall;wall_work[resource]+=wall
                if event.get("background"):background_work[resource]+=cost
                elif event.get("phase") in DEDICATED_VERIFIER_PHASES or _is_arbitration_phase(str(event.get("phase") or "")):
                    dedicated_work[resource]+=cost
                    if _is_arbitration_phase(str(event.get("phase") or "")):arbitration_work[resource]+=cost
                causal[resource]=max(causal[resource],float(event.get("causal_finish_s",0.)))
            actor=str(event.get("actor") or "")
            if actor in network.node_shards:
                resource=resources[0]
                shard=int(network.node_shards[actor])
                if shard<k:block_shard_ready[shard]=max(block_shard_ready[shard],finish)
                group_name=str(event.get("group") or "")
                parts=group_name.split(":")
                if len(parts)>=3 and parts[0]=="pbft":
                    try:
                        proof_shard=int(parts[1]);proof_slot=max(0,int(parts[2])-1)
                        block_slot_ready[(proof_shard,proof_slot)]=max(block_slot_ready[(proof_shard,proof_slot)],finish)
                        if (proof_shard,proof_slot) in normal_slots:
                            normal_pre_active_work[resource]+=cost
                            if resource.startswith(("NODE:","VERIFIER:")):
                                normal_pbft_slot_node_work[(proof_shard,proof_slot,resource)]+=cost
                    except ValueError:pass
    service_task_rows=[]
    for tx_id in [str(tx["id"]) for tx in transactions]:
        groups=tx_groups.get(tx_id,[])
        tx=tx_by_id[tx_id];involved=sorted({int(tx["source"]),int(tx["target"])})
        slot=int(slot_records[tx_id]["slot"])
        ready=max([releases[tx_id],float(slot_records[tx_id]["service_release_s"])] +
                  [block_slot_ready.get((s,slot),block_shard_ready[s]) for s in involved])
        final_ready=ready
        for group in groups:
            phase=str(group[0].get("phase") or "")
            quorum=_stage_quorum(group,k,network.config)
            foreground_finishes=[]
            accepted_finishes=[]
            lane_finishes=defaultdict(list);lane_accepted=defaultdict(list)
            for event in group:
                resources=_event_resources(event,network,scheme)
                cost=float(event.get("cpu_seconds",event.get("seconds",0.)))
                wall=float(event.get("seconds",0.))
                if not math.isfinite(cost) or cost<0 or not math.isfinite(wall) or wall<0:
                    raise ValueError("invalid measured service")
                start=max(max(available[resource],ready) for resource in resources);finish=start+cost
                for resource in resources:
                    available[resource]=finish
                    active_work[resource]+=cost;active_wall[resource]+=wall;wall_work[resource]+=wall
                    if event.get("background"):background_work[resource]+=cost
                    elif phase in DEDICATED_VERIFIER_PHASES or _is_arbitration_phase(phase):
                        dedicated_work[resource]+=cost
                        if _is_arbitration_phase(phase):arbitration_work[resource]+=cost
                    causal[resource]=max(causal[resource],float(event.get("causal_finish_s",0.)))
                if not event.get("background"):
                    foreground_finishes.append(finish)
                    if event.get("accepted") is True:accepted_finishes.append(finish)
                    lane=event.get("group_lane")
                    if lane is not None:
                        lane_finishes[str(lane)].append(finish)
                        if event.get("accepted") is True:lane_accepted[str(lane)].append(finish)
                for resource in resources:
                    transaction_resource_finishes[tx_id].append((resource,start,finish,phase,bool(event.get("background"))))
                    service_task_rows.append(dict(tx=tx_id,resource=resource,phase=phase,
                        cpu_seconds=cost,start_s=start,finish_s=finish,background=bool(event.get("background"))))
            if lane_finishes:
                lane_ready=[]
                for lane,finishes in lane_finishes.items():
                    ordered=sorted(finishes);accepted=sorted(lane_accepted[lane])
                    if quorum is not None and len(accepted)>=quorum:
                        lane_ready.append(accepted[quorum-1])
                    elif quorum is not None and len(ordered)>=quorum:
                        lane_ready.append(ordered[quorum-1])
                    else:
                        lane_ready.append(max(ordered))
                final_ready=max(lane_ready,default=final_ready)
                ready=final_ready
            elif foreground_finishes:
                ordered=sorted(foreground_finishes)
                accepted=sorted(accepted_finishes)
                if quorum is not None and len(accepted)>=quorum:
                    final_ready=accepted[quorum-1]
                elif quorum is not None and len(ordered)>=quorum:
                    final_ready=ordered[quorum-1]
                else:
                    final_ready=max(ordered)
                ready=final_ready
        transaction_ends[tx_id]=final_ready

    epoch_ready=max(transaction_ends.values(),default=0.)
    epoch_finish=epoch_ready
    for group in post_groups:
        group_finishes=[];group_lane_finishes=defaultdict(list)
        group_lane_accepted=defaultdict(list)
        for event in group:
            resources=_event_resources(event,network,scheme)
            cost=float(event.get("cpu_seconds",event.get("seconds",0.)))
            wall=float(event.get("seconds",0.))
            if not math.isfinite(cost) or cost<0 or not math.isfinite(wall) or wall<0:
                raise ValueError("invalid measured epoch service")
            start=max(max(available[resource],epoch_ready) for resource in resources);finish=start+cost
            group_finishes.append(finish)
            lane=event.get("group_lane")
            if lane is not None:
                group_lane_finishes[str(lane)].append(finish)
                if event.get("accepted") is True:group_lane_accepted[str(lane)].append(finish)
            for resource in resources:
                available[resource]=finish
                active_work[resource]+=cost;active_wall[resource]+=wall;wall_work[resource]+=wall
                if event.get("background"):background_work[resource]+=cost
                elif event.get("phase") in DEDICATED_VERIFIER_PHASES:
                    dedicated_work[resource]+=cost
                causal[resource]=max(causal[resource],float(event.get("causal_finish_s",0.)))
                service_task_rows.append(dict(tx="__epoch__",resource=resource,
                    phase=event.get("phase"),cpu_seconds=cost,start_s=start,
                    finish_s=finish,background=bool(event.get("background"))))
        if group_finishes:
            quorum=_stage_quorum(group,k,network.config)
            if group_lane_finishes:
                lane_ready=[]
                for lane,finishes in group_lane_finishes.items():
                    ordered=sorted(finishes)
                    accepted=sorted(group_lane_accepted[lane])
                    if quorum and len(accepted)>=quorum:
                        lane_ready.append(accepted[quorum-1])
                    elif quorum:
                        lane_ready.append(max(ordered))
                    else:
                        lane_ready.append(max(ordered))
                epoch_ready=max(lane_ready,default=epoch_ready)
            else:
                ordered=sorted(group_finishes)
                epoch_ready=ordered[min(len(ordered),quorum)-1] if quorum else max(ordered)
            epoch_finish=max(epoch_finish,epoch_ready)

    shard_resources={}
    shard_clocks=[];shard_active_work=[]
    for shard in range(k):
        resources=["SHARD:"+str(shard),"CONTRACT_SHARD:"+str(shard)]
        if scheme=="Auncel":
            resources.extend("NODE:"+str(actor) for actor,node_shard in network.node_shards.items()
                             if int(node_shard)==shard)
            resources.extend("VERIFIER:"+str(actor) for actor,node_shard in network.node_shards.items()
                             if int(node_shard)==shard)
        shard_resources[shard]=resources
        shard_clocks.append(max((available[resource] for resource in resources),default=0.))
        shard_active_work.append(sum(active_work[resource] for resource in resources))
    shard_transaction_load=[sum(1 for tx in transactions
        if shard in {int(tx["source"]),int(tx["target"])}) for shard in range(k)]
    load_mean=sum(shard_transaction_load)/k if k else 0.
    load_sd=float(np.std(shard_transaction_load,ddof=1)) if k>1 else 0.
    load_range=max(shard_transaction_load)-min(shard_transaction_load) if shard_transaction_load else 0
    block_horizons=[(max(s)+1)*interval if s else 0. for s in slots]
    completed=sum(tx["state"] in ("COMMIT","ABORT") for tx in transactions)
    terminal_ids=[str(tx["id"]) for tx in transactions if tx["state"] in ("COMMIT","ABORT")]
    min_release=min((releases[tx_id] for tx_id in terminal_ids),default=0.0)
    max_completion=max((transaction_ends.get(tx_id,releases.get(tx_id,min_release)) for tx_id in terminal_ids),default=min_release)
    makespan=max(0.,max_completion-min_release)
    protocol_active_makespan=max(available.values(),default=0.)
    active_makespan=max(transaction_ends.values(),default=0.)-min_release if transaction_ends else 0.
    calls=network.gssc_services;evm=sum(c["evm_cpu_s"] for c in calls);wait=sum(c["protocol_wait_s"] for c in calls)
    views=[e for e in network.service_events if e["phase"]=="evm_view_cpu"]
    causal_makespan=max(causal.values(),default=0.)

    normal_ids={str(tx["id"]) for tx in transactions if not tx.get("arbitration_triggered",False)}
    normal_completed=sum(str(tx["id"]) in normal_ids and tx["state"] in ("COMMIT","ABORT") for tx in transactions)
    normal_shard_load=[sum(1 for tx in transactions if str(tx["id"]) in normal_ids and
        shard in {int(tx["source"]),int(tx["target"])}) for shard in range(k)]
    normal_shard_capacity_load=[0.0]*k
    for tx in transactions:
        if str(tx["id"]) not in normal_ids:continue
        involved=sorted({int(tx["source"]),int(tx["target"])})
        weight=(1.0/len(involved)
                if scheme in ("Auncel","DCchain")
                and capacity_load_mode=="fractional" and involved
                else 1.0)
        for shard in involved:normal_shard_capacity_load[shard]+=weight
    normal_shard_cpu=[0.0]*k;normal_node_cpu=defaultdict(float)
    for task in service_task_rows:
        if str(task.get("tx")) not in normal_ids:continue
        resource=str(task["resource"]);cost=float(task["cpu_seconds"])
        if resource.startswith(("SHARD:","CONTRACT_SHARD:")):
            normal_shard_cpu[int(resource.split(":",1)[1])]+=cost
        elif resource.startswith(("NODE:","VERIFIER:")):
            actor=resource.split(":",1)[1]
            if actor in network.node_shards:
                normal_node_cpu[(int(network.node_shards[actor]),actor)]+=cost
    for resource,cost in normal_pre_active_work.items():
        if resource.startswith(("NODE:","VERIFIER:")):
            actor=resource.split(":",1)[1]
            if actor in network.node_shards:
                normal_node_cpu[(int(network.node_shards[actor]),actor)]+=cost
    normal_shard_capacity_block_counts=[
        (fixed_capacity_blocks if fixed_capacity_blocks is not None
         else int(math.ceil(load/capacity))) if load else 0
        for load in normal_shard_capacity_load]
    normal_block_horizons=[blocks*interval
                           for blocks in normal_shard_capacity_block_counts]
    normal_shard_capacity_overload=[
        bool(fixed_capacity_blocks is not None
             and load>fixed_capacity_blocks*capacity)
        for load in normal_shard_capacity_load]
    pbft_slot_durations=defaultdict(float)
    for (shard,slot,resource),cost in normal_pbft_slot_node_work.items():
        pbft_slot_durations[(shard,slot)]=max(pbft_slot_durations[(shard,slot)],cost)
    pbft_once_s=max(pbft_slot_durations.values(),default=0.)
    normal_shard_durations=[]
    for shard in range(k):
        normal_shard_durations.append(max(normal_block_horizons[shard],normal_shard_cpu[shard],pbft_once_s))
    normal_service_makespan=max(normal_shard_durations,default=0.)
    normal_service_capacity_tps=normal_completed/normal_service_makespan if normal_service_makespan else 0.
     normal_shard_busiest_node_cpu=[];normal_shard_cpu_per_block=[]
    normal_shard_quorum_cpu_per_block=[]
    normal_shard_execution_cpu_per_block=[]
    normal_shard_capacity_tps=[]
    for shard in range(k):
        capacity_load=(normal_shard_capacity_load[shard]
                       if scheme in ("Auncel","DCchain")
                       and capacity_load_mode=="fractional"
                       else normal_shard_load[shard])
        blocks=(fixed_capacity_blocks
                if fixed_capacity_blocks is not None and capacity_load
                else max(1,int(math.ceil(capacity_load/capacity))))
        busiest=max((cost for (node_shard,_),cost in normal_node_cpu.items()
                     if node_shard==shard),default=0.)
        per_block=busiest/blocks
        execution_per_block=normal_shard_cpu[shard]/blocks
        node_costs=sorted(cost/blocks for (node_shard,_),cost in normal_node_cpu.items()
                          if node_shard==shard)
        quorum=(2*(len(node_costs)-1)//3+1) if node_costs else 0
        quorum_per_block=node_costs[quorum-1] if quorum else 0.
        normal_shard_busiest_node_cpu.append(busiest)
        normal_shard_cpu_per_block.append(per_block)
        normal_shard_quorum_cpu_per_block.append(quorum_per_block)
        normal_shard_execution_cpu_per_block.append(execution_per_block)
        normal_shard_capacity_tps.append(
            capacity/max(interval,execution_per_block,quorum_per_block)
            if capacity_load else 0.)
    aggregate_normal_shard_capacity_tps=sum(normal_shard_capacity_tps)

        shard_service_capacity_tps=[];shard_active_cpu_per_block=[]
    for s in range(k):
        blocks=max(1,int(math.ceil(shard_transaction_load[s]/capacity)))
        per_block=shard_active_work[s]/blocks
        shard_active_cpu_per_block.append(per_block)
        shard_service_capacity_tps.append(shard_transaction_load[s]/max(shard_clocks[s]-min_release,interval))

    service_resource_prefixes=("SHARD:","CONTRACT_SHARD:")
    if scheme=="Auncel":service_resource_prefixes+=("NODE:","VERIFIER:")
    transaction_service_resources={r:t for r,t in available.items()
                                   if r.startswith(service_resource_prefixes)}
    contract_shard_clocks={r:t for r,t in available.items()
                           if r.startswith("CONTRACT_SHARD:")}
    contract_shard_work={r:t for r,t in active_work.items()
                         if r.startswith("CONTRACT_SHARD:")}
    network.service_available_time=dict(available)
    report=dict(
        resource_available_time_s=dict(available),
        node_clocks_s={r:t for r,t in available.items() if r.startswith("NODE:")},
        verifier_clocks_s={r:t for r,t in available.items() if r.startswith("VERIFIER:")},
        arbitrator_clocks_s={r:t for r,t in available.items() if r.startswith("ARBITRATOR:")},
        shard_clocks_s=shard_clocks,
        protocol_shard_clocks_s=[max((available[prefix+n] for prefix in (("NODE:","VERIFIER:") if scheme=="Auncel" else ("NODE:",)) for n,s in network.node_shards.items() if int(s)==shard),default=0.) for shard in range(k)],
        transaction_node_clocks_s={r:t for r,t in transaction_service_resources.items() if r.startswith("NODE:")},
        transaction_verifier_clocks_s={r:t for r,t in transaction_service_resources.items() if r.startswith("VERIFIER:")},
        transaction_shard_lane_clocks_s={r:t for r,t in transaction_service_resources.items() if r.startswith("SHARD:")},
        transaction_resource_clocks_s=dict(transaction_service_resources),
        gssc_clock_s=max([available.get("GSSC",0.)]+list(contract_shard_clocks.values())),
        contract_shard_clocks_s=contract_shard_clocks,
        contract_shard_active_work_s=contract_shard_work,
        dc_global_clock_s=available.get("DC_GLOBAL",0.),
        node_causal_finish_s={n:causal[n] for n in network.node_shards},
        resource_causal_finish_s=dict(causal),
        shard_causal_finish_s=[max((causal[n] for n,s in network.node_shards.items() if int(s)==shard),default=0.) for shard in range(k)],
        gssc_causal_finish_s=max([causal.get("GSSC",0.)]+
                                 [causal.get(r,0.) for r in contract_shard_clocks]),
        dc_global_causal_finish_s=causal.get("DC_GLOBAL",0.),
        causal_finish_makespan_s=causal_makespan,
        active_work_s=dict(active_work),transaction_service_work_s=dict(transaction_service_resources),
        active_wall_work_s=dict(active_wall),measured_wall_work_s=dict(wall_work),
        dedicated_verifier_work_s=dict(dedicated_work),arbitration_work_s=dict(arbitration_work),
        background_work_s=dict(background_work),
        background_policy="background CPU is scheduled on its own resource but never advances a transaction stage barrier",
        quorum=7,block_capacity=capacity,block_interval_s=interval,
        shard_transaction_load=shard_transaction_load,shard_transaction_load_mean=load_mean,
        shard_transaction_load_sd=load_sd,shard_transaction_load_range=load_range,
        workload_balance_policy="deterministic seeded selection from real XBlock rows; each transaction counts once per involved shard",
        block_occupancy=[dict(shard=s,slot=b,transactions=n) for s,blocks in enumerate(slots) for b,n in sorted(blocks.items())],
        transaction_block_slots=slot_records,transaction_service_completion_s=dict(transaction_ends),
        pbft_block_lane_duration_s={str(s):float(t) for s,t in getattr(network,"block_pipeline_shard_duration_s",{}).items()},
        pbft_block_slot_duration_s={"%d:%d"%(s,b):float(t) for (s,b),t in getattr(network,"block_pipeline_shard_slot_duration_s",{}).items()},
        block_slot_service_ready_s={"%d:%d"%(s,b):t for (s,b),t in block_slot_ready.items()},
        block_capacity_horizons_s=block_horizons,global_service_makespan_s=makespan,
        epoch_service_completion_s=epoch_finish,
        active_service_makespan_s=active_makespan,protocol_active_makespan_s=protocol_active_makespan,
        active_service_bottleneck=[r for r,t in transaction_service_resources.items() if t==max(transaction_service_resources.values(),default=0.)],
        shard_active_cpu_work_s=shard_active_work,shard_active_cpu_per_block_s=shard_active_cpu_per_block,
        shard_service_capacity_tps=shard_service_capacity_tps,
        service_capacity_tps=normal_service_capacity_tps,
        all_terminal_completion_tps=(completed/makespan if makespan else 0.),
        normal_service_completed=normal_completed,
        normal_service_makespan_s=normal_service_makespan,
        normal_shard_transaction_load=normal_shard_load,
        normal_shard_capacity_load=normal_shard_capacity_load,
        normal_shard_capacity_block_counts=normal_shard_capacity_block_counts,
        normal_shard_capacity_overload=normal_shard_capacity_overload,
        normal_shard_capacity_overload_count=sum(normal_shard_capacity_overload),
        fixed_capacity_blocks=fixed_capacity_blocks,
        capacity_window_mode=("fixed" if fixed_capacity_blocks is not None else "measured"),
        normal_shard_active_cpu_s=normal_shard_cpu,
        normal_shard_block_horizons_s=normal_block_horizons,
        normal_shard_service_durations_s=normal_shard_durations,
        normal_shard_capacity_tps=normal_shard_capacity_tps,
        normal_shard_busiest_node_cpu_s=normal_shard_busiest_node_cpu,
        normal_shard_cpu_per_block_s=normal_shard_cpu_per_block,
        normal_shard_quorum_cpu_per_block_s=normal_shard_quorum_cpu_per_block,
        normal_shard_execution_cpu_per_block_s=normal_shard_execution_cpu_per_block,
        aggregate_normal_shard_capacity_tps=aggregate_normal_shard_capacity_tps,
        pbft_single_parallel_service_s=pbft_once_s,
        pbft_single_block_node_durations_s={"%d:%d:%s"%(s,b,r):v for (s,b,r),v in normal_pbft_slot_node_work.items()},
        observed_workload_tps=(completed/makespan if makespan else 0.),
        bottleneck=[r for r,t in available.items() if t==max(available.values(),default=0.)],
        completed=completed,committed=sum(tx["state"]=="COMMIT" for tx in transactions),
        min_release_time_s=min_release,max_completion_time_s=max_completion,
        service_task_count=len(service_task_rows),
         formula=("common throughput = terminal transactions / global service "
                  "makespan; terminal includes commit and abort outcomes. "
                  "Auncel uses its configured round-robin worker lanes; DCchain "
                  "retains its existing shard-lane service model. Per-shard CPU, "
                  "validator CPU and block-capacity horizons remain diagnostics."),
        assumptions=(("Auncel transaction-local work is scheduled on the individual "
                      "round-robin service nodes selected by Consensus.service_node; "
                      "DCchain retains the existing shard-lane accounting; one "
                      "cross-shard contract operation reserves every touched "
                      "contract-shard lane and completes at the maximum lane-ready "
                      "time; validator and arbitrator CPU runs on independent node "
                      "resources; q-th foreground response closes a parallel stage; "
                      "deterministic PyEVM state transitions remain sequential; "
                      "epoch root/finalization work is measured once after local "
                      "decisions and added only to latency; no CPU or wait value is "
                      "synthesized or scaled")),
        gssc_call_count=len(calls),gssc_epoch_finalization_calls=sum(c["epoch_finalization"] for c in calls),
        gssc_evm_cpu_total_s=evm,gssc_evm_cpu_mean_s=evm/len(calls) if calls else 0.,
        gssc_execution_model="measured EVM execution is booked at the observed CPU duration on every involved virtual shard lane; a cross-shard call waits for the maximum lane-ready time; the raw EVM CPU total still counts each executed call once",
        gssc_protocol_view_count=len(views),gssc_protocol_view_cpu_s=sum(e.get("cpu_seconds",e["seconds"]) for e in views),
        gssc_protocol_view_accounting="measured protocol-read CPU is assigned to the executing shard lane; each read remains a separate ordered service event unless it belongs to an explicit parallel stage",
        gssc_all_measured_cpu_s=evm+sum(e.get("cpu_seconds",e["seconds"]) for e in views),
        dedicated_verifier_cpu_total_s=sum(dedicated_work.values()),
        arbitration_cpu_total_s=sum(arbitration_work.values()),
        dedicated_verifier_phases=sorted(DEDICATED_VERIFIER_PHASES),
        evm_measurement_boundary="writes: process CPU in PyEVM chain.apply_transaction; protocol reads: process CPU in PyEVM backend.call; measured values only",
        gssc_wait_total_s=wait,gssc_wait_mean_s=wait/len(calls) if calls else 0.,
        gssc_receipt_wall_total_s=sum(c["receipt_wall_s"] for c in calls),
        gssc_confirmation_policy="confirmation and receipt waits remain causal latency only; no GSSC wait advances service occupancy",
    )
    common_throughput_tps=completed/makespan if makespan else 0.
    committed_tps=sum(tx["state"]=="COMMIT" for tx in transactions)/makespan if makespan else 0.
    return dict(
         throughput_tps=common_throughput_tps,
         committed_throughput_tps=committed_tps,
         finalization_tps=(completed/makespan if makespan else 0.),
         service_capacity_tps=common_throughput_tps,
        observed_workload_tps=(completed/makespan if makespan else 0.),
        global_service_makespan_s=makespan,active_service_makespan_s=active_makespan,
        all_terminal_completion_tps=(completed/makespan if makespan else 0.),
        normal_service_completed=normal_completed,
        normal_service_makespan_s=normal_service_makespan,
        pbft_single_parallel_service_s=pbft_once_s,
        active_service_target_s=float(network.config.get("active_service_target_s",0.94)),
        active_service_target_met=active_makespan<=float(network.config.get("active_service_target_s",0.94)),
        service_accounting=report,shard_transaction_load=shard_transaction_load,
        shard_transaction_load_mean=load_mean,shard_transaction_load_sd=load_sd,
        shard_transaction_load_range=load_range,
        normal_shard_capacity_load=normal_shard_capacity_load,
        normal_shard_capacity_block_counts=normal_shard_capacity_block_counts,
        normal_shard_capacity_overload=normal_shard_capacity_overload,
        normal_shard_capacity_overload_count=sum(normal_shard_capacity_overload),
        fixed_capacity_blocks=fixed_capacity_blocks,
        capacity_window_mode=("fixed" if fixed_capacity_blocks is not None else "measured"),
        normal_shard_capacity_tps=normal_shard_capacity_tps,
        normal_shard_busiest_node_cpu_s=normal_shard_busiest_node_cpu,
        normal_shard_cpu_per_block_s=normal_shard_cpu_per_block,
        normal_shard_quorum_cpu_per_block_s=normal_shard_quorum_cpu_per_block,
        normal_shard_execution_cpu_per_block_s=normal_shard_execution_cpu_per_block,
        aggregate_normal_shard_capacity_tps=aggregate_normal_shard_capacity_tps,
        **{key:value for key,value in report.items() if key.startswith("gssc_") and isinstance(value,(int,float))},
    )

def summary(transactions,network,wall_s,gas=0,epoch_service_s=0.,
           epoch_finality_start_s=None,epoch_finality_finish_s=None,
           dcchain_finality_start_s=None,dcchain_finality_finish_s=None,
           scheme=None,k=None,capacity_load_mode=None,
           fixed_capacity_blocks=None):
    n=len(transactions);commit=sum(t["state"]=="COMMIT" for t in transactions)
    requested=[t for t in transactions if t["arbitration_triggered"]]
    if k is None:k=1+max(max(int(t["source"]),int(t["target"])) for t in transactions)
    timeline=resource_timeline(transactions,network,k,scheme=scheme,
                               capacity_load_mode=capacity_load_mode,
                               fixed_capacity_blocks=fixed_capacity_blocks)
     background_latency=defaultdict(float);background_network=defaultdict(float)
    arbitration_crypto=defaultdict(float)
    for event in network.service_events:
        tx_id=event.get("tx")
        if tx_id is None:continue
        phase=event["phase"]
        if event.get("background"):
            background_latency[str(tx_id)]+=float(event["seconds"])
        if _is_arbitration_phase(phase):
            arbitration_crypto[str(tx_id)]+=float(event["seconds"])
    for event in network.trace_events:
        if not event.get("background"):continue
        tx_id=_message_tx_id(event)
        if tx_id is None:continue
        background_network[tx_id]=max(background_network[tx_id],
                                      max(0.,float(event["delivered"])-float(event["sent"])))
    for tx in transactions:
        tx_id=str(tx["id"])
        extra=background_latency[tx_id]+background_network[tx_id]
        tx["latency_adjustment_s"]=extra
        tx["background_verifier_latency_s"]=background_latency[tx_id]
        tx["background_verifier_network_wait_s"]=background_network[tx_id]
        tx["arbitration_crypto_latency_s"]=arbitration_crypto[tx_id]
        tx["latency_s"]=float(tx["latency_s"])+extra
               tx["latency_before_epoch_finality_s"]=float(tx["latency_s"])

        epoch_wait_values=[]
    if (scheme=="Auncel" and epoch_finality_finish_s is not None):
        finish=float(epoch_finality_finish_s)
        start=(float(epoch_finality_start_s)
               if epoch_finality_start_s is not None else finish)
        epoch_stage=max(0.,finish-start)
        for tx in transactions:
            wait=epoch_stage
            tx["epoch_global_finality_wait_s"]=epoch_stage
            tx["epoch_global_finality_finish_s"]=finish
                       base_end_to_end=float(tx.get("end_to_end_latency_s",
                                      tx.get("latency_s",0.)))
            tx["global_end_to_end_latency_s"]=base_end_to_end+epoch_stage
            tx["latency_s"]=float(tx["latency_s"])+wait
                        tx["end_to_end_latency_s"]=base_end_to_end+epoch_stage
            epoch_wait_values.append(wait)
    else:
        for tx in transactions:
            tx["epoch_global_finality_wait_s"]=0.
            tx["epoch_global_finality_finish_s"]=None
            tx["global_end_to_end_latency_s"]=None
            epoch_wait_values.append(0.)
    epoch_global_wait_mean=(float(np.mean(epoch_wait_values))
                            if epoch_wait_values else 0.)
    dcchain_global_finality_duration=(
        max(0.,float(dcchain_finality_finish_s)-float(dcchain_finality_start_s))
        if dcchain_finality_start_s is not None and dcchain_finality_finish_s is not None
        else 0.)
    if scheme=="DCchain" and dcchain_global_finality_duration:
               for tx in transactions:
            base_end_to_end=float(tx.get("end_to_end_latency_s",
                                      tx.get("latency_s",0.)))
            tx["dcchain_global_finality_wait_s"]=dcchain_global_finality_duration
            tx["global_end_to_end_latency_s"]=(base_end_to_end+
                                                dcchain_global_finality_duration)
            tx["end_to_end_latency_s"]=tx["global_end_to_end_latency_s"]
            tx["latency_s"]=(float(tx["latency_s"])+
                              dcchain_global_finality_duration)
    bg_latency_values=[tx["background_verifier_latency_s"] for tx in transactions]
    bg_network_values=[tx["background_verifier_network_wait_s"] for tx in transactions]
    arb_crypto_values=[tx["arbitration_crypto_latency_s"] for tx in transactions if tx.get("arbitration_triggered")]
    result=dict(submitted=n,committed=commit,transaction_success_rate=commit/n,
                throughput_method=timeline["service_accounting"]["formula"],
                auncel_completion_latency_s=(
                    float(np.mean([
                        float(t.get("global_end_to_end_latency_s")
                              or t.get("end_to_end_latency_s")
                              or t["latency_s"])
                        for t in transactions if t.get("cross") and
                        t.get("state") in ("COMMIT","ABORT")]))
                    if scheme=="Auncel" and any(
                        t.get("cross") and t.get("state") in ("COMMIT","ABORT")
                        for t in transactions) else None),
                auncel_cross_shard_latency_count=(
                    sum(1 for t in transactions if t.get("cross") and
                        t.get("state") in ("COMMIT","ABORT"))
                    if scheme=="Auncel" else None),
                dcchain_completion_latency_s=(
                    float(np.mean([t["latency_s"] for t in transactions
                                   if t.get("cross") and
                                   t.get("state") in ("COMMIT","ABORT")]))
                    if scheme=="DCchain" else None),
                epoch_finalization_service_s=epoch_service_s,
                epoch_global_finality_duration_s=(
                    max(0.,float(epoch_finality_finish_s)-float(epoch_finality_start_s))
                    if epoch_finality_start_s is not None and epoch_finality_finish_s is not None
                    else 0.),
                epoch_global_finality_wait_s_mean=epoch_global_wait_mean,
                dcchain_global_finality_duration_s=dcchain_global_finality_duration,
                dcchain_global_finality_start_s=(
                    float(dcchain_finality_start_s)
                    if dcchain_finality_start_s is not None else None),
                dcchain_global_finality_finish_s=(
                    float(dcchain_finality_finish_s)
                    if dcchain_finality_finish_s is not None else None),
                arbitration_attempts=len(requested),arbitration_successes=sum(t["adjudicated"] for t in requested),
                arbitration_success_rate=(sum(t["adjudicated"] for t in requested)/len(requested) if requested else None),
                pvss_execution_s=sum(v for k,v in network.cpu_times.items() if k.startswith("pvss")),
                contract_gas=gas,total_messages=sum(network.protocol_counts.values()),total_bytes=sum(network.protocol_sizes.values()),
                setup_messages=sum(network.counts.values())-sum(network.protocol_counts.values()),
                setup_bytes=sum(network.sizes.values())-sum(network.protocol_sizes.values()),
                latency_adjustment_s=float(np.mean([tx["latency_adjustment_s"] for tx in transactions])) if transactions else 0.,
                background_verifier_latency_s=float(np.mean(bg_latency_values)) if bg_latency_values else 0.,
                background_verifier_network_wait_s=float(np.mean(bg_network_values)) if bg_network_values else 0.,
                arbitration_crypto_latency_s=float(np.mean(arb_crypto_values)) if arb_crypto_values else 0.,
                wall_s=wall_s)
    result.update(timeline)
    result["throughput_method"]=(
        "common terminal throughput = terminal transactions / global service "
        "makespan; terminal outcomes include COMMIT and ABORT for both schemes")
    result["service_accounting"]["formula"]=result["throughput_method"]
    result["service_accounting"]["service_capacity_tps"]=result["service_capacity_tps"]
    result["dcchain_aggregate_capacity_tps"]=(
        timeline["aggregate_normal_shard_capacity_tps"])
    result["service_accounting"]["dcchain_global_finality_duration_s"] = (
        dcchain_global_finality_duration if scheme=="DCchain" else 0.0)
    result["service_accounting"]["dcchain_global_finality_start_s"] = (
        float(dcchain_finality_start_s)
        if scheme=="DCchain" and dcchain_finality_start_s is not None else None)
    result["service_accounting"]["dcchain_global_finality_finish_s"] = (
        float(dcchain_finality_finish_s)
        if scheme=="DCchain" and dcchain_finality_finish_s is not None else None)
    epoch_normal=[t["latency_s"] for t in transactions if t.get("epoch_settled")]
    result["normal_epoch_completion_latency_s"]=float(np.mean(epoch_normal)) if epoch_normal else None
    result["normal_epoch_settled_count"]=len(epoch_normal)
    for key in ("pvss","cross_shard","arbitration","consensus","contract"):
        result[key+"_messages"]=network.protocol_counts[key];result[key+"_bytes"]=network.protocol_sizes[key]
    result["communication_bytes_per_tx"]=result["total_bytes"]/n
    for mode in (1,2,3):
        selected=[t for t in requested if scheme=="Auncel" and t["fault"]==mode]
        result["arb%d_count"%mode]=len(selected)
        result["arb%d_latency_s"%mode]=float(np.mean([t["latency_s"] for t in selected])) if selected else None
        result["arb%d_latency_local_s"%mode]=(float(np.mean([t["latency_before_epoch_finality_s"] for t in selected]))
                                              if selected else None)
    local_normal=[t["latency_before_epoch_finality_s"] for t in transactions
                  if t.get("cross") and not t.get("arbitration_triggered")]
    result["normal_native_completion_latency_local_s"]=(
        float(np.mean(local_normal)) if local_normal else None)
    result["protocol_processing_s"]=sum(t["protocol_processing_s"] for t in transactions)
        dc_phases={
        "dcchain_proof_signing_cpu_s":"baseline_bls_sign",
        "dcchain_proof_aggregation_cpu_s":"baseline_bls_aggregate",
        "dcchain_proof_verification_cpu_s":"baseline_bls_verify",
        "dcchain_state_verification_cpu_s":"baseline_state_verification",
        "dcchain_state_commit_cpu_s":"baseline_state_commit",
        "dcchain_final_reply_signing_cpu_s":"baseline_reply_sign",
        "dcchain_final_reply_verification_cpu_s":"baseline_reply_verify",
        "dcchain_vrf_generation_cpu_s":"baseline_vrf_generation",
        "dcchain_vrf_verification_cpu_s":"baseline_vrf_verification",
        "dcchain_vrf_processing_cpu_s":"baseline_vrf_processing",
    }
    for metric,phase in dc_phases.items():result[metric]=float(network.cpu_times[phase]) if scheme=="DCchain" else None
    result["dcchain_active_cpu_s"]=(sum(network.cpu_times[p] for p in dc_phases.values()) if scheme=="DCchain" else None)
    return result

def aggregate(rows,fields):
    groups=defaultdict(list)
    for row in rows:groups[tuple(row[f] for f in fields)].append(row)
    result=[]
    for key,items in groups.items():
        out=dict(zip(fields,key));out["repetitions"]=len(items)
        for metric in items[0]:
            values=[r[metric] for r in items if r[metric] is not None]
            if metric in fields or metric=="seed" or not values or not isinstance(values[0],(float,int)) or isinstance(values[0],bool):continue
            if not values:continue
            out[metric+"_mean"]=float(np.mean(values));out[metric+"_sd"]=float(np.std(values,ddof=1)) if len(values)>1 else 0.
        result.append(out)
    return result
