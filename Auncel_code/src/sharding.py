import hashlib, random
from .nodes import Node, seed_for

class ShardTopology(list):
    def __init__(self, shards, seed):
        super().__init__(shards)
        self.seed = seed
        self.subepoch_accounting = {}
        self.verification_chain_nodes = []

    def accounting_for(self, shard, subepoch):
        key = (int(shard), int(subepoch))
        if key not in self.subepoch_accounting:
            nodes = [n for n in self[int(shard)] if not n.malicious]
            if not nodes:
                nodes = list(self[int(shard)])
            rng = random.Random(seed_for(self.seed,
                                         "accounting:%d:%d" % key))
            selected = rng.choice(nodes)
            self.subepoch_accounting[key] = selected
            for node in self[int(shard)]:
                node.accounting = False
                if node.role == "shard_accounting":
                    node.role = "shard_verifier"
            selected.accounting = True
            selected.role = "shard_accounting"
        return self.subepoch_accounting[key]

def assign_nodes(k, seed, config):
    n=config["nodes_per_shard"]; bad=config["malicious_per_shard"]
    if n!=10 or not 0<=bad<=3 or k<2: raise ValueError("Require k>=2, 10 nodes/shard, <=3 Byzantine/shard")
    rng=random.Random(seed_for(seed,"assignment"))
    ids=list(range(k*n));rng.shuffle(ids)
    corrupt=set(ids[:k*bad]);honest=ids[k*bad:];byzantine=ids[:k*bad]
    rng.shuffle(honest);rng.shuffle(byzantine)
    shards=[]
    for s in range(k):
        members=honest[s*(n-bad):(s+1)*(n-bad)]+byzantine[s*bad:(s+1)*bad]
        rng.shuffle(members)
        nodes=[Node(i,s,i in corrupt,seed,role="shard_verifier") for i in members]
        chosen=rng.choice([node for node in nodes if not node.malicious] or nodes)
        chosen.accounting=True
        chosen.role="shard_accounting"
        shards.append(nodes)
    assert len({x.id for shard in shards for x in shard})==k*n
    topology=ShardTopology(shards,seed)
     topology.verification_chain_nodes=[next(node for node in shard if node.accounting)
                                       for shard in topology]
    return topology

def account_shard(address, k, seed):
    return int.from_bytes(hashlib.sha256((str(seed)+":"+address.lower()).encode()).digest(),"big")%k
