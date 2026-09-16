"""Discrete message delivery with directed-link serialization and measured CPU service."""
import gzip, hashlib, heapq, json, random, time
from contextlib import contextmanager
from collections import Counter, defaultdict
from .nodes import seed_for

def encode(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),default=str).encode()

class Network:
    def __init__(self, config, seed, output):
        self.config=config;self.seed=seed;self.now=0.;self.seq=0;self.pending=[]
        self.links={};self.cpu={};self.counts=Counter();self.sizes=Counter();self.cpu_times=Counter()
        self.protocol_counts=Counter();self.protocol_sizes=Counter();self.excluded_setup_s=0.
        self.stream=gzip.open(output,"wt",encoding="utf-8") if output is not None else None
        self.trace_events=[]
        self.service_events=[];self.service_tx=None;self.service_enabled=False
        self.service_background=False;self.node_shards={};self.gssc_services=[]
        self.service_epoch=False
        self.arbitrator_ids=set()
        self.service_group=None;self.service_quorum=None;self.service_lane=None
        self.contract_shards=None
        self.service_available_time={}
        self.service_nested_wall=0.;self.service_nested_cpu=0.;self.compute_depth=0;self.compute_actors=[]
        self.shard_queues=[];self.shard_block_assignments={}
        self.block_pipeline_parallel=False;self.block_pipeline_lanes=0
        self.block_pipeline_shard_duration_s={}
        # Causal PBFT duration for each independently pipelined shard block.
        # The aggregate shard duration remains available for diagnostics, but
        # transaction latency uses the duration of its own block slot.
        self.block_pipeline_shard_slot_duration_s={}

    @staticmethod
    def _thread_cpu_time():
        """Return CPU time for the executing worker thread."""
        return getattr(time,"thread_time",time.process_time)()

    def init_shard_queues(self,k,capacity,interval):
        if k<=0 or capacity<=0 or interval<=0:
            raise ValueError("invalid shard queue configuration")
        self.shard_queues=[defaultdict(int) for _ in range(k)]
        self.shard_queue_capacity=int(capacity);self.shard_queue_interval=float(interval)
        self.shard_block_assignments={}

    def schedule_shards(self,tx_id,involved,submitted=0.0):
        """Reserve one block slot in every shard touched by a transaction."""
        if not self.shard_queues:raise RuntimeError("shard queues are not initialized")
        shards=sorted(set(int(s) for s in involved))
        if not shards or any(s<0 or s>=len(self.shard_queues) for s in shards):
            raise ValueError("invalid involved shard set")
        slot=0
        while any(self.shard_queues[s][slot]>=self.shard_queue_capacity for s in shards):
            slot+=1
        for s in shards:self.shard_queues[s][slot]+=1
        start=max(float(submitted),slot*self.shard_queue_interval)
        self.shard_block_assignments[tx_id]=dict(shards=shards,slot=slot,service_release_s=slot*self.shard_queue_interval)
        return slot,start

    def record_service(self,actor,phase,elapsed,resource=None,cpu_seconds=None,
                       causal_start_s=None,resources=None):
        if self.service_enabled and not phase.endswith("_setup"):
            event=dict(tx=self.service_tx,actor=str(actor),
                resource=resource or str(actor),phase=phase,seconds=elapsed,
                cpu_seconds=float(elapsed if cpu_seconds is None else cpu_seconds),
                background=self.service_background,
                epoch_finalization=self.service_epoch,
                group=self.service_group,group_quorum=self.service_quorum,
                causal_start_s=float(self.now if causal_start_s is None else causal_start_s),
                causal_finish_s=self.now)
            if self.service_lane is not None:
                event["group_lane"]=str(self.service_lane)
            if resources is not None:
                event["resources"]=list(dict.fromkeys(str(value) for value in resources))
            self.service_events.append(event)

    @contextmanager
    def service_scope(self,group,quorum=None,lane=None):
        previous=(self.service_group,self.service_quorum,self.service_lane)
        self.service_group=group;self.service_quorum=quorum;self.service_lane=lane
        try:yield
        finally:self.service_group,self.service_quorum,self.service_lane=previous

    def compute_global(self,actor,phase,function,*args,**kwargs):
        before=len(self.service_events)
        result=self.compute(actor,phase,function,*args,**kwargs)
        for event in self.service_events[before:]:event["resource"]="DC_GLOBAL"
        return result

    def compute(self, actor, phase, function, *args, **kwargs):
        nested_before=self.service_nested_wall;nested_cpu_before=self.service_nested_cpu;event_before=len(self.service_events)
        self.compute_depth+=1;self.compute_actors.append(str(actor))
        causal_start=max(self.now,self.cpu.get(str(actor),0.))
        try:
            start=time.perf_counter();cpu_start=self._thread_cpu_time();result=function(*args,**kwargs)
            elapsed=time.perf_counter()-start;cpu_elapsed=self._thread_cpu_time()-cpu_start
        finally:self.compute_actors.pop();self.compute_depth-=1
        self.now=max(self.now,self.cpu.get(str(actor),0))+elapsed
        self.cpu[str(actor)]=self.now;self.cpu_times[phase]+=elapsed
        for event in self.service_events[event_before:]:event["causal_finish_s"]=self.now
        if phase.endswith("_setup"):self.excluded_setup_s+=elapsed
        self.record_service(actor,phase,
            max(0.,elapsed-(self.service_nested_wall-nested_before)),
            cpu_seconds=max(0.,cpu_elapsed-(self.service_nested_cpu-nested_cpu_before)),
            causal_start_s=causal_start)
        if isinstance(result,bool) and len(self.service_events)>event_before:
            self.service_events[-1]["accepted"]=bool(result)
        return result

    def compute_background(self, actor, phase, function, *args, **kwargs):
              nested_before=self.service_nested_wall;nested_cpu_before=self.service_nested_cpu;event_before=len(self.service_events)
        self.compute_depth+=1;self.compute_actors.append(str(actor))
        causal_start=self.now
        try:
            start=time.perf_counter();cpu_start=self._thread_cpu_time();result=function(*args,**kwargs)
            elapsed=time.perf_counter()-start;cpu_elapsed=self._thread_cpu_time()-cpu_start
        finally:self.compute_actors.pop();self.compute_depth-=1
        self.cpu_times[phase]+=elapsed
        for event in self.service_events[event_before:]:event["causal_finish_s"]=self.now
        previous=self.service_background;self.service_background=True
        try:self.record_service(actor,phase,
            max(0.,elapsed-(self.service_nested_wall-nested_before)),
            cpu_seconds=max(0.,cpu_elapsed-(self.service_nested_cpu-nested_cpu_before)),
            causal_start_s=causal_start)
        finally:self.service_background=previous
        if isinstance(result,bool) and len(self.service_events)>event_before:
            self.service_events[-1]["accepted"]=bool(result)
        return result

    def send(self,sender,receiver,kind,payload,category="cross_shard",signature=None):
        self.seq+=1
        envelope=dict(sender=str(sender),receiver=str(receiver),kind=kind,payload=payload,
                      signature=signature.hex() if isinstance(signature,bytes) else signature)
        raw=encode(envelope);link=(str(sender),str(receiver))
        begin=max(self.now,self.links.get(link,0.));end=begin+8*len(raw)/(self.config["bandwidth_mbps"]*1e6)
        self.links[link]=end
        # Seeded per-link/phase/message delay; payload hash retained for audit.
        rng=random.Random(seed_for(self.seed,(sender,receiver,kind,self.seq)))
        arrival=end+rng.uniform(*self.config["network_delay_s"])
        heapq.heappush(self.pending,(arrival,self.seq,envelope,category,len(raw),self.now))
        self.counts[category]+=1;self.sizes[category]+=len(raw)
        if kind not in ("PVSS_PUBLIC_KEYS","BLS_PUBLIC_SHARES"):
            self.protocol_counts[category]+=1;self.protocol_sizes[category]+=len(raw)
        return arrival

    def drain(self):
        delivered=[]
        while self.pending:
            at,seq,envelope,category,size,sent=heapq.heappop(self.pending)
            self.now=max(self.now,at)
            event=dict(seq=seq,sent=sent,delivered=at,bytes=size,category=category,**envelope)
            self.trace_events.append(event)
            if self.stream:self.stream.write(json.dumps(event)+"\n")
            delivered.append(envelope)
        return delivered

    def drain_background(self):
              delivered=[]
        current=self.now
        while self.pending:
            at,seq,envelope,category,size,sent=heapq.heappop(self.pending)
            event=dict(seq=seq,sent=sent,delivered=at,bytes=size,category=category,background=True,**envelope)
            self.trace_events.append(event)
            if self.stream:self.stream.write(json.dumps(event)+"\n")
            delivered.append(envelope)
        self.now=current
        return delivered

    def drain_threshold(self,qualifying_arrivals,quorum):
                ordered=sorted(float(t) for t in qualifying_arrivals)
        if len(ordered)<int(quorum):
            return self.drain()
        threshold=ordered[int(quorum)-1];delivered=[];current=self.now
        while self.pending:
            at,seq,envelope,category,size,sent=heapq.heappop(self.pending)
            event=dict(seq=seq,sent=sent,delivered=at,bytes=size,category=category,
                background=at>threshold,**envelope)
            self.trace_events.append(event)
            if self.stream:self.stream.write(json.dumps(event)+"\n")
            delivered.append(envelope)
        self.now=max(current,threshold)
        return delivered

    def merge_parallel_lane(self,lane,offset=0.0):
                for event in lane.trace_events:
            merged=dict(event);self.seq+=1;merged["seq"]=self.seq
            merged["sent"]=float(event["sent"])+offset;merged["delivered"]=float(event["delivered"])+offset
            self.trace_events.append(merged)
            if self.stream:self.stream.write(json.dumps(merged)+"\n")
        for event in lane.service_events:
            merged=dict(event);merged["causal_finish_s"]=float(event["causal_finish_s"])+offset
            self.service_events.append(merged)
        self.counts.update(lane.counts);self.sizes.update(lane.sizes)
        self.protocol_counts.update(lane.protocol_counts);self.protocol_sizes.update(lane.protocol_sizes)
        self.cpu_times.update(lane.cpu_times);self.excluded_setup_s+=lane.excluded_setup_s
        self.now=max(self.now,float(offset)+lane.now)

    def broadcast(self,sender,receivers,kind,payload,category,signature=None):
        before=self.now
        for receiver in receivers:
            if str(receiver)!=str(sender):self.send(sender,receiver,kind,payload,category,signature)
        delivered=self.drain()
        if kind in ("PVSS_PUBLIC_KEYS","BLS_PUBLIC_SHARES"):self.excluded_setup_s+=self.now-before
        return delivered

    def close(self):
        self.drain()
        if self.stream:self.stream.close()
