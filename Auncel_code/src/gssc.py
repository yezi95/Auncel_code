"""Actual Solidity/PyEVM execution"""
import json, math, os, time
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_abi import encode as abi_encode
from eth_tester import EthereumTester, PyEVMBackend
from web3 import Web3, EthereumTesterProvider
import solcx
from .nodes import seed_for
from .arbitration_params import arbitration_parameters

def compile_contract(root):
    local=root/".solcx"
    if (local/"solc-v0.8.24").exists():os.environ["SOLCX_BINARY_PATH"]=str(local)
    if not any(str(v)=="0.8.24" for v in solcx.get_installed_solc_versions()):raise RuntimeError("Install solc 0.8.24 before running")
    code=(root/"contracts/GSSC.sol").read_text(encoding="utf-8")
    return solcx.compile_source(code,output_values=["abi","bin"],solc_version="0.8.24",optimize=True,optimize_runs=200,evm_version="paris")["<stdin>:GSSCSettlement"]

class GSSC:
    def __init__(self,artifact,shards,txs,ledger,config,seed,network,output):
        self.config=config;self.net=network;self.contracts={};self.gas=0;self.calls=0;self.setup_gas=0;self.epoch_id=seed;self.cost_records=[]
        self.pending_arbitration=[];self.pending_arbitration_accounts=set();self.arbitration_batch_calls=0;self.arbitration_batched_proofs=0;self.arbitration_batch_fallbacks=0
        self.receipts=(output/"contract_receipts.jsonl").open("w",encoding="utf-8");self.audit=(output/"fund_audit.jsonl").open("w",encoding="utf-8");self.arbitration_costs=(output/"arbitration_costs.jsonl").open("w",encoding="utf-8")
        self.shards=shards;self.ledger=ledger;self.local_records=[]
        self.tx_shards={str(tx.id):tuple(sorted({int(tx.source),int(tx.target)})) for tx in txs}
        self.tx_party_shards={str(tx.id):{tx.sender:int(tx.source),tx.receiver:int(tx.target)} for tx in txs}
        self.view_count=0
        labels={x for tx in txs for x in (tx.sender,tx.receiver)};self.arbiters=[next(n for n in shard if n.accounting) for shard in shards];labels.update("node:"+str(n.id) for shard in shards for n in shard)
        self.tester=EthereumTester(PyEVMBackend(genesis_parameters={"gas_limit":config["gssc_block_gas_limit"],"timestamp":1700000000}));self.w3=Web3(EthereumTesterProvider(self.tester));self.chain_id=int(self.w3.eth.chain_id);self.faucet=self.w3.eth.accounts[0];self.w3.eth.default_account=self.faucet
        self.address={};self.signing_keys={};keys=[]
        self.expected_balances={};self.expected_reserve={};self.expected_reward_reserve={};self.quorums={}
         self.replica_nonces={};self.replica_versions={};self.replica_deals={}
        for label in sorted(labels):
            key=seed_for(seed,"evm:"+label).to_bytes(32,"big");self.address[label]=Account.from_key(key).address;self.signing_keys[self.address[label]]=key;keys.append(key)
        for key in keys:self.tester.add_account(key.hex())
        escrow={label:0 for label in labels}
        for tx in txs:
            if tx.cross:
                escrow[tx.sender]+=config["party_bond_wei"]
                escrow[tx.receiver]+=config["party_bond_wei"]
        arbiter_credit=(len(txs)+1)*(config["arbiter_bond_wei"]+config["gas_cost_wei"])
        for node in self.arbiters:escrow["node:"+str(node.id)]=arbiter_credit
        cross_counts={asset:sum(1 for tx in txs if tx.cross and tx.asset==asset) for asset in {tx.asset for tx in txs if tx.cross}}
        reward_budgets={asset:count*len(self.arbiters)*config["minimum_arbitration_reward_wei"] for asset,count in cross_counts.items()}
        required=sum(escrow.values())+len(labels)*config["gssc_gas_reserve_wei"]+sum(reward_budgets.values())
        if required>=self.w3.eth.get_balance(self.faucet):raise ValueError("XBlock escrow plus gas reserves exceed eth-tester faucet")
        for label,address in self.address.items():
            amount=escrow.get(label,0)+config["gssc_gas_reserve_wei"]
            if amount:self.w3.eth.wait_for_transaction_receipt(self.w3.eth.send_transaction({"from":self.faucet,"to":address,"value":amount,"gas":21000}))
        self.epoch=self.timestamp();self.members=[self.address["node:"+str(n.id)] for n in self.arbiters];self.ait_entries={asset:[] for asset in {tx.asset for tx in txs if tx.cross}}
        factory=self.w3.eth.contract(abi=artifact["abi"],bytecode=artifact["bin"])
        for asset in sorted(self.ait_entries):
            self.replica_nonces[asset]={};self.replica_versions[asset]={};self.replica_deals[asset]={}
            _,q,_=arbitration_parameters(config,len(shards));receipt=self._execute(factory.constructor(self.members,q,config["request_bond_wei"],config["arbiter_bond_wei"],config["gas_cost_wei"],config["minimum_arbitration_reward_wei"]),self.faucet,setup=True,deploy=True)
            c=self.w3.eth.contract(address=receipt.contractAddress,abi=artifact["abi"]);self.contracts[asset]=c
            deployed_q=int(c.functions.quorum().call({"from":self.faucet}))
            if deployed_q!=q:raise AssertionError("deployed GSSC quorum mismatch")
            self.quorums[asset]=deployed_q;self._check_client_hashes(c)
            participants={p for tx in txs if tx.asset==asset for p in (tx.sender,tx.receiver)}
            self._execute(c.functions.fundRewardReserve(),self.faucet,reward_budgets[asset],setup=True)
            for party in sorted(participants):
                if escrow[party]:self._execute(c.functions.deposit(),self.address[party],escrow[party],setup=True)
            for address in self.members:self._execute(c.functions.deposit(),address,arbiter_credit,setup=True)
            for shard,nodes in enumerate(shards):self._execute(c.functions.registerShard(shard,[self.address["node:"+str(n.id)] for n in nodes]),self.faucet,setup=True)
            self.conserve(c)
            self.expected_balances[asset]={a:self.view(c.functions.balances(a)) for a in self.address.values()}
            self.expected_reserve[asset]=0
            self.expected_reward_reserve[asset]=reward_budgets[asset]
        self.epoch=self.timestamp()+2;self.net.now=0;self.net.links.clear();self.net.cpu.clear()

    def timestamp(self):return self.w3.eth.get_block("latest").timestamp
    def _contract_resources(self):
        shards=self.net.contract_shards
        if shards is None and self.net.service_epoch:
            shards=range(len(self.shards))
        if shards is None and self.net.service_tx is not None:
            shards=self.tx_shards.get(str(self.net.service_tx))
        if shards is None:return None
        values=sorted({int(shard) for shard in shards})
        return ["CONTRACT_SHARD:"+str(shard) for shard in values] or None

    def projected_confirmation_timestamp(self):
        interval=self.config["gssc_block_interval_s"]
        return max(self.timestamp()+interval,
            self.epoch+math.ceil(self.net.now/interval)*interval)
    def _execute(self,fn,caller,value=0,setup=False,deploy=False):
        service_start=self.net.now;evm_cpu=[0.];receipt_wall=0.
        fn_name=getattr(fn,"fn_name","constructor")
        limit=self.config["gssc_deploy_gas_limit"] if deploy else self.config["gssc_tx_gas_limit"]
        if not setup and fn_name=="submitBallotsBatch":
            limit=self.config.get("gssc_batch_gas_limit",self.config["gssc_block_gas_limit"])
        deployment_estimate=None
        if deploy:
            deployment_estimate=int(fn.estimate_gas({"from":caller,"value":value}))
            limit=max(limit,deployment_estimate)
            block_limit=min(self.config["gssc_block_gas_limit"],self.w3.eth.get_block("latest").gasLimit)
            if limit>block_limit:raise RuntimeError("GSSC deployment gas estimate exceeds block limit: %d > %d"%(limit,block_limit))
        if not setup:
            self.net.send(caller,"GSSC","CONTRACT_CALL",dict(caller=caller,to=getattr(fn,"address",None),data=fn._encode_transaction_data(),value=value),"contract");self.net.drain();desired=self.projected_confirmation_timestamp()
            if desired>self.timestamp()+1:self.tester.time_travel(desired)
        chain=self.tester.backend.chain;apply_transaction=chain.apply_transaction
        def measured_apply(*args,**kwargs):
            cpu_start=time.process_time()
            try:return apply_transaction(*args,**kwargs)
            finally:evm_cpu[0]+=time.process_time()-cpu_start
        chain.apply_transaction=measured_apply
        try:
            gas_price=int(self.config.get("gas_price_wei",2000000000))
            start=time.perf_counter();h=fn.transact({"from":caller,"value":value,"gas":limit,"gasPrice":gas_price})
            receipt_start=time.perf_counter();receipt=self.w3.eth.wait_for_transaction_receipt(h);receipt_wall=time.perf_counter()-receipt_start;elapsed=time.perf_counter()-start
        finally:chain.apply_transaction=apply_transaction
        if receipt.status!=1:raise RuntimeError("GSSC failed: %s gasUsed=%d gasLimit=%d%s"%(getattr(fn,"fn_name","constructor"),receipt.gasUsed,limit," (gas exhausted; inspect gas limit)" if receipt.gasUsed==limit else " (execution reverted)"))
        self.calls+=1
        if setup:self.setup_gas+=receipt.gasUsed
        else:
            self.gas+=receipt.gasUsed;self.net.cpu_times["contract_execution"]+=elapsed;self.net.now=max(self.net.now,self.timestamp()-self.epoch)+elapsed;self.net.send("GSSC",caller,"CONTRACT_RECEIPT",dict(tx=h.hex(),status=receipt.status,gas=receipt.gasUsed),"contract");self.net.drain()
            self.net.record_service("GSSC","evm_transaction_cpu",evm_cpu[0],
                                    resources=self._contract_resources())
            self.net.gssc_services.append(dict(tx=self.net.service_tx,operation=getattr(fn,"fn_name","deploy"),
                evm_cpu_s=evm_cpu[0],legacy_execution_wall_s=elapsed,receipt_wall_s=receipt_wall,
                protocol_wait_s=max(0.,self.net.now-service_start-elapsed),gas_used=receipt.gasUsed,
                block_number=receipt.blockNumber,epoch_finalization=getattr(fn,"fn_name","")=="finalizeEpoch"))
        self.receipts.write(json.dumps(dict(tx=h.hex(),operation=getattr(fn,"fn_name","deploy"),caller=caller,value=value,value_unit="wei",gas=receipt.gasUsed,gas_limit=limit,deployment_gas_estimate=deployment_estimate,gas_price_wei=receipt.effectiveGasPrice,gas_paid_wei=receipt.gasUsed*receipt.effectiveGasPrice,wall_s=elapsed,timestamp=self.timestamp(),setup=setup,status=receipt.status))+"\n");return receipt
    def call(self,c,name,caller,*args,value=0):
        receipt=self._execute(getattr(c.functions,name)(*args),caller,value)
        terminal_state={"completeNormal":2,"expire":3,"closeUnresolved":3}.get(name)
        if terminal_state is not None:self._mark_terminal_cache(c,args[0],terminal_state)
        self.conserve(c);return receipt
    def view(self,fn):
        if not self.net.service_enabled or not self.net.compute_depth:
            return fn.call({"from":self.faucet,"gas":200000})
        backend=self.tester.backend;original=backend.call;cpu=[0.];wall=[0.]
        def measured_call(*args,**kwargs):
            c=time.process_time();w=time.perf_counter()
            try:return original(*args,**kwargs)
            finally:
                cpu[0]+=time.process_time()-c;wall[0]+=time.perf_counter()-w
        backend.call=measured_call
        try:return fn.call({"from":self.faucet,"gas":200000})
        finally:
            backend.call=original
            actor=self.net.compute_actors[-1]
            shard=self.net.node_shards.get(actor)
            if shard is None and self.net.service_tx is not None:
                shard=self.tx_party_shards.get(str(self.net.service_tx),{}).get(actor)
            resources=(["CONTRACT_SHARD:"+str(int(shard))]
                       if shard is not None else self._contract_resources())
            self.view_count+=1
            if self.net.service_group is None:
                with self.net.service_scope("gssc_view:%d"%self.view_count):
                    self.net.record_service(actor,"evm_view_cpu",cpu[0],resources=resources)
            else:
                self.net.record_service(actor,"evm_view_cpu",cpu[0],resources=resources)
            self.net.service_nested_wall+=wall[0]
            self.net.service_nested_cpu+=cpu[0]
    def conserve(self,c):assert self.view(c.functions.accounted())==self.w3.eth.get_balance(c.address),"GSSC conservation"
    def snapshot(self,c,tx):
        addresses=[self.address[tx.sender],self.address[tx.receiver]]+self.members;return dict(credits={a:self.view(c.functions.balances(a)) for a in addresses},reserve=self.view(c.functions.penaltyReserve()),reward_reserve=self.view(c.functions.rewardReserve()))
    def ballot_digest(self,c,deal_id,mode,evidence,support,epoch=None):
        evidence_hash=self.w3.keccak(evidence)
        payload=abi_encode(["uint256","address","uint256","bytes32","uint8","bytes32","uint256","bool"],
            [self.chain_id,c.address,self.epoch_id if epoch is None else int(epoch),deal_id,int(mode),evidence_hash,0,bool(support)])
        return self.w3.keccak(payload)
    def _registration_digest(self,c,sender,terms):
        fields=["address","uint256","uint256","bytes32","uint256","uint256","uint256",
            "uint256","uint256","uint256","uint256","uint256","bytes32"]
        terms_hash=self.w3.keccak(abi_encode(fields,list(terms)))
        return self.w3.keccak(abi_encode(["uint256","address","address","bytes32"],
            [self.chain_id,c.address,sender,terms_hash]))
    def _check_client_hashes(self,c):
        sender=self.faucet;receiver=next(iter(self.address.values()))
        txhash=self.w3.keccak(b"gssc-client-txid-check")
        local_id=self.w3.solidity_keccak(["address","address","uint256","uint256","bytes32"],
            [sender,receiver,7,self.epoch_id,txhash])
        chain_id=c.functions.txId(sender,receiver,7,self.epoch_id,txhash).call({"from":self.faucet})
        if bytes(local_id)!=bytes(chain_id):raise AssertionError("client GSSC transaction ID encoding mismatch")
        terms=(receiver,7,self.epoch_id,txhash,1,2,3,4,5,6,7,8,self.w3.keccak(b"gssc-registration-check"))
        local_registration=self._registration_digest(c,sender,terms)
        chain_registration=c.functions.registrationDigest(sender,terms).call({"from":self.faucet})
        if bytes(local_registration)!=bytes(chain_registration):raise AssertionError("client GSSC registration digest mismatch")
        deal_id=self.w3.keccak(b"gssc-client-ballot-check");evidence=b"gssc-client-evidence-check"
        for mode in (1,2,3):
            for support in (False,True):
                local=self.ballot_digest(c,deal_id,mode,evidence,support,epoch=0)
                onchain=c.functions.ballotDigestFor(deal_id,mode,self.w3.keccak(evidence),support).call(
                    {"from":self.faucet})
                if bytes(local)!=bytes(onchain):raise AssertionError("client GSSC ballot digest mismatch")
    def _read_cached_sender_terms(self,asset,sender):
        return (self.replica_nonces[asset].get(sender,0),
                self.replica_versions[asset].get(sender,0))
    def _read_cached_version(self,asset,address):
        return self.replica_versions[asset].get(address,0)
    def cached_deal_state(self,asset,deal_id):
        deal=self.replica_deals[asset].get(bytes(deal_id))
        if deal is None:raise AssertionError("unknown GSSC deal in replica cache")
        return int(deal["state"])
    def _record_registered_deal(self,asset,sender,receiver,deal_id,nonce):
        deals=self.replica_deals[asset];key=bytes(deal_id)
        if key in deals:raise AssertionError("duplicate GSSC deal in replica cache")
        current=self.replica_nonces[asset].get(sender,0)
        if current!=int(nonce):raise AssertionError("GSSC nonce replica drift")
        deals[key]=dict(sender=sender,receiver=receiver,state=1)
        self.replica_nonces[asset][sender]=current+1
    def _mark_terminal_cache(self,c,deal_id,state):
        asset=next((asset for asset,contract in self.contracts.items()
                    if contract.address==c.address),None)
        if asset is None:raise AssertionError("unknown GSSC contract in replica cache")
        deal=self.replica_deals[asset].get(bytes(deal_id))
        if deal is None:raise AssertionError("unknown GSSC deal in replica cache")
        state=int(state)
        if state not in (2,3):raise AssertionError("invalid terminal GSSC state")
        if deal["state"] in (2,3):
            if deal["state"]!=state:raise AssertionError("GSSC terminal state changed")
            return
        if deal["state"]!=1:raise AssertionError("invalid cached GSSC state")
        for address in (deal["sender"],deal["receiver"]):
            self.replica_versions[asset][address]=self.replica_versions[asset].get(address,0)+1
        deal["state"]=state
    def open(self,tx,secret,delta_prime_s):
        self.flush_arbitration_proofs(accounts={tx.sender,tx.receiver})
        c=self.contracts[tx.asset];sender=self.address[tx.sender];receiver=self.address[tx.receiver];before=self.snapshot(c,tx)
        with self.net.service_scope("gssc_open_terms:%s"%tx.id):
            source_node=self.consensus.leaders[tx.source].id
            target_node=self.consensus.leaders[tx.target].id
            nonce,sv=self.net.compute(source_node,"gssc_terms_cache_read",
                self._read_cached_sender_terms,tx.asset,sender)
            rv=self.net.compute(target_node,"gssc_terms_cache_read",
                self._read_cached_version,tx.asset,receiver)
        delta=self.config["network_delay_delta_s"];epsilon=self.config["timeout_jitter_epsilon_s"];delta1=delta+delta_prime_s+epsilon;delta2=2*delta+delta_prime_s+epsilon
        now=max(self.timestamp(),self.epoch+math.ceil(self.net.now));expires=now+self.config["transaction_deadline_s"]
        interval=self.config["gssc_block_interval_s"]
        due1=min(expires-3,max(now+3*interval+1,now+math.ceil(delta1)))
        due2=min(expires-2,max(due1+1,now+4*interval+1,now+math.ceil(delta2)))
        ack=min(expires-1,max(due2+1,now+5*interval+1))
        txhash=bytes.fromhex(tx.original_hash[2:]);terms=(receiver,nonce,self.epoch_id,txhash,tx.amount,self.config["party_bond_wei"],sv,rv,due1,due2,ack,expires,self.w3.keccak(secret))
        id=self.net.compute(tx.sender,"gssc_txid_client_hash",self.w3.solidity_keccak,
            ["address","address","uint256","uint256","bytes32"],
            [sender,receiver,nonce,self.epoch_id,txhash])
        registration_digest=self._registration_digest(c,sender,terms)
        registration_signature=Account.sign_message(encode_defunct(primitive=registration_digest),
            private_key=self.signing_keys[sender]).signature
        self.call(c,"registerAndAccept",receiver,sender,terms,bytes(registration_signature))
        self._record_registered_deal(tx.asset,sender,receiver,id,nonce)
        event_base=self.net.now
        return dict(c=c,id=id,tx=tx,before=before,due=[due1,due2,ack,expires],
            event_base_s=event_base,event_due=[event_base+delta1,event_base+delta2],
            requester=None,votes=[],secret=secret,delta_s=delta,
            delta_prime_s=delta_prime_s,epsilon_s=epsilon,delta1_s=delta1,
            delta2_s=delta2,onchain_delta1_s=due1-now,onchain_delta2_s=due2-now,
            delta1_expired=False,delta2_expired=False)
    def wait_until(self,t):
        self.net.now=max(self.net.now,t-self.epoch)
        if self.timestamp()<t:self.tester.time_travel(t);self.tester.mine_block()
    def cast_votes(self,d,voters,mode=None,evidence=b""):
        signatures=[]
        mode=int(mode if mode is not None else d["tx"].fault)
        if mode==1:self.wait_until(d["due"][0])
        elif mode in (2,3):
            self.wait_until(d["due"][1])
        self.call(d["c"],"admitArbitrationRequest",d["requester"],d["id"],mode)
         self.call(d["c"],"request",d["requester"],d["id"],mode,evidence,
                  value=self.config["request_bond_wei"])
        onchain=self.view(d["c"].functions.getDeal(d["id"]))
        if not bool(onchain[19]) or int(onchain[20]) != mode:
            d["request_rejected"]=True;d["proof_queued"]=False
            d["invalid_request_penalty_wei"]=self.config["request_bond_wei"]
            d["requester"]=None
            self.expire(d)
            return False
        _,q,_=arbitration_parameters(self.config,len(self.arbiters))
        with self.net.service_scope("gssc_arb_cert:%s"%d["tx"].id,q):
            for address,support in voters:
                node=next(n for n,a in zip(self.arbiters,self.members) if a==address)
                digest=self.net.compute(node.id,"arbitration_ballot_digest_local",
                    self.ballot_digest,d["c"],d["id"],mode,evidence,support)
                signed=self.net.compute(node.id,"arbitration_certificate_sign",Account.sign_message,encode_defunct(primitive=digest),private_key=self.signing_keys[address])
                signature=bytes(signed.signature)
                self.net.send(node.id,d["requester"],"ARBITRATION_CERTIFICATE_SHARE",dict(tx=d["tx"].id,support=support,signature=signature.hex()),"arbitration")
                signatures.append(signature)
        self.net.drain()
        d["votes"].extend(voters)
        try:
            d["c"].functions.submitBallotsBatch([d["id"]],[[support for _,support in voters]],[signatures]).call(
                {"from":self.faucet,"value":0,"gas":self.config.get("gssc_batch_gas_limit",self.config["gssc_block_gas_limit"])})
        except Exception:
            state=int(self.view(d["c"].functions.transactionState(d["id"])))
            if state==1:
                if d.get("requester"):
                    self.call(d["c"],"closeUnresolved",d["requester"],d["id"])
                    d["proof_queued"]=False;d["proof_submitted"]=True
                    return False
            if state in (2,3):
                self._mark_terminal_cache(d["c"],d["id"],state)
                d["proof_queued"]=False;d["proof_submitted"]=True
                return False
            raise RuntimeError("GSSC ballot certificate preflight failed for %s" % d["tx"].id)
        d["proof_queued"]=True
        self.pending_arbitration.append(dict(asset=d["tx"].asset,c=d["c"],deal=d,
            id=d["id"],mode=mode,evidence=evidence,support=[support for _,support in voters],
            signatures=signatures))
        self.pending_arbitration_accounts.update((d["tx"].sender,d["tx"].receiver))
        return True
    def remaining(self,d):return d["due"][3]-max(self.timestamp(),self.epoch+self.net.now)
    def expire(self,d):self.wait_until(d["due"][3]);self.call(d["c"],"expire",self.address[d["tx"].sender],d["id"])
    def finish_audit(self,d,adjudicated):
        tx=d["tx"];c=d["c"];before=d["before"];queued=d.get("proof_queued",False)
        if queued:
            commit=bool(adjudicated and tx.fault==3);state=2 if commit else 3;after=None
        else:
            after=self.snapshot(c,tx);state=self.view(c.functions.transactionState(d["id"]));commit=state==2
            if state not in (2,3):raise AssertionError("nonterminal GSSC")
        expected={a:0 for a in before["credits"]};sender=self.address[tx.sender];receiver=self.address[tx.receiver]
        reserve=d.get("invalid_request_penalty_wei",0)
        if d["requester"]:expected[d["requester"]]+=self.config["request_bond_wei"]
        if adjudicated:
            guilty=receiver if tx.fault==1 else sender
            winners=[a for a,valid in d["votes"] if valid]
            base_reward=self.config["minimum_arbitration_reward_wei"]*len(winners)
            pool=self.config["party_bond_wei"]+base_reward
            for address,valid in d["votes"]:
                expected[address]-=self.config["gas_cost_wei"]
                reserve+=self.config["gas_cost_wei"]
                if not valid:
                    expected[address]-=self.config["arbiter_bond_wei"]
                    pool+=self.config["arbiter_bond_wei"]
            each,remainder=divmod(pool,len(winners));reserve+=remainder
            for address in winners:expected[address]+=each
        if not queued:
            for a,delta in expected.items():self.expected_balances[tx.asset][a]+=delta
            self.expected_reserve[tx.asset]+=reserve
            if adjudicated:self.expected_reward_reserve[tx.asset]-=base_reward
        actual=({a:after["credits"][a]-before["credits"][a] for a in expected} if after is not None else None)
        settlement_expected=dict(expected)
        if actual is not None:
            assert expected==actual,(tx.id,"fund delta",expected,actual)
            assert after["reserve"]-before["reserve"]==reserve
            expected_reward_delta=(-base_reward if adjudicated else 0)
            assert after["reward_reserve"]-before["reward_reserve"]==expected_reward_delta
        d["settlement_queued"]=queued
        for account,action in ((sender,"DEBIT_COMMIT" if commit else "REFUND_ABORT"),(receiver,"CREDIT_COMMIT" if commit else "NO_CREDIT_ABORT")):
            action_hash=self.w3.keccak(text=action)
            key=self.w3.keccak(abi_encode(["uint256","bytes32","address"],[self.epoch_id,d["id"],account]))
            value=self.w3.keccak(abi_encode(["bytes32"],[action_hash]))
            if not queued:assert self.view(c.functions.AIT(key))==value
            self.ait_entries[tx.asset].append((key,value))
        d["queued_commit"]=commit;d["audit_expected_delta"]=settlement_expected;d["audit_expected_reserve"]=reserve;d["audit_expected_reward_delta"]=(-base_reward if adjudicated else 0);d["audit_applied"]=not queued;d["ait_entries"]=list(zip(
            [self.w3.keccak(abi_encode(["uint256","bytes32","address"],[self.epoch_id,d["id"],self.address[tx.sender]])),
             self.w3.keccak(abi_encode(["uint256","bytes32","address"],[self.epoch_id,d["id"],self.address[tx.receiver]]) )],
            [self.w3.keccak(abi_encode(["bytes32"],[self.w3.keccak(text="DEBIT_COMMIT" if commit else "REFUND_ABORT")])),
             self.w3.keccak(abi_encode(["bytes32"],[self.w3.keccak(text="CREDIT_COMMIT" if commit else "NO_CREDIT_ABORT")]))]))
        self.audit.write(json.dumps(dict(transaction=tx.id,asset=tx.asset,mode=tx.fault,commit=commit,adjudicated=adjudicated,settlement_queued=queued,epoch_expected_delta=settlement_expected,expected=expected,actual=actual,reserve_delta=reserve,state=state,deferred_proof=queued,timeouts={k:d[k] for k in ("delta_s","delta_prime_s","epsilon_s","delta1_s","delta2_s","onchain_delta1_s","onchain_delta2_s","delta1_expired","delta2_expired")},passed=True))+"\n");return commit

    def _apply_terminal_audit(self,d,adjudicated):
        if d.get("audit_applied"):return
        tx=d["tx"]
        if adjudicated:
            deltas=d["audit_expected_delta"]
            reserve=d["audit_expected_reserve"]
            reward_delta=d.get("audit_expected_reward_delta",0)
        else:
            deltas={a:0 for a in d["before"]["credits"]}
            if d.get("requester"):deltas[d["requester"]]+=self.config["request_bond_wei"]
            reserve=d.get("invalid_request_penalty_wei",0);reward_delta=0
        for address,delta in deltas.items():self.expected_balances[tx.asset][address]+=delta
        self.expected_reserve[tx.asset]+=reserve
        self.expected_reward_reserve[tx.asset]+=reward_delta
        d["audit_applied"]=True

    def _submit_ballot_batch(self,c,batch):
        """Submit one real batch, isolating a bad deferred item safely.

        Solidity batches are atomic. A stale/expired certificate must not
        revert unrelated valid certificates, so a failed preflight is split
        recursively until the offending item is isolated. That item follows
        closeUnresolved/expire and therefore receives no reward or penalty.
        """
        ids=[item["id"] for item in batch]
        supports=[item["support"] for item in batch]
        signatures=[item["signatures"] for item in batch]
        limit=self.config.get("gssc_batch_gas_limit",self.config["gssc_block_gas_limit"])
        fn=c.functions.submitBallotsBatch(ids,supports,signatures)
        try:
            fn.call({"from":self.faucet,"value":0,"gas":limit})
        except Exception:
            if len(batch)>1:
                mid=max(1,len(batch)//2)
                return self._submit_ballot_batch(c,batch[:mid])+self._submit_ballot_batch(c,batch[mid:])
            item=batch[0];d=item["deal"];state=int(self.view(c.functions.transactionState(item["id"])))
            if state in (2,3):
                self._mark_terminal_cache(c,item["id"],state)
                self.arbitration_batch_fallbacks+=1
                info=self.view(c.functions.getDeal(item["id"]));q=int(self.view(c.functions.quorum()))
                self._apply_terminal_audit(d,int(info[22])>=q)
                d["proof_queued"]=False;d["proof_submitted"]=True
                return 1
            if state==1:
                info=self.view(c.functions.getDeal(item["id"]));q=int(self.view(c.functions.quorum()))
                now=max(self.timestamp(),self.epoch+math.ceil(self.net.now))
                if now>=d["due"][3]:
                    self.arbitration_batch_fallbacks+=1
                    if d.get("requester"):self.call(c,"closeUnresolved",d["requester"],item["id"])
                    else:self.expire(d)
                    self._apply_terminal_audit(d,False)
                    d["proof_queued"]=False;d["proof_submitted"]=True
                    return 1
                if int(info[22])<q and d.get("requester"):
                    self.arbitration_batch_fallbacks+=1
                    self.call(c,"closeUnresolved",d["requester"],item["id"])
                    self._apply_terminal_audit(d,False)
                    d["proof_queued"]=False;d["proof_submitted"]=True
                    return 1
            raise RuntimeError("GSSC ballot batch preflight failed for %s" % d["tx"].id)
        previous_shards=self.net.contract_shards
        self.net.contract_shards=sorted({shard for item in batch
            for shard in self.tx_shards[str(item["deal"]["tx"].id)]})
        try:self.call(c,"submitBallotsBatch",self.faucet,ids,supports,signatures)
        finally:self.net.contract_shards=previous_shards
        self.arbitration_batch_calls+=1;self.arbitration_batched_proofs+=len(batch)
        for item in batch:
            d=item["deal"]
            state=int(self.view(c.functions.transactionState(item["id"])))
            if state in (2,3):self._mark_terminal_cache(c,item["id"],state)
            adjudicated=True
            if state==1:
                requester=d.get("requester")
                if not requester:raise AssertionError("unresolved deal has no requester")
                self.call(c,"closeUnresolved",requester,item["id"])
                state=int(self.view(c.functions.transactionState(item["id"])))
                adjudicated=False
            expected_state=2 if d.get("queued_commit",False) else 3
            if state!=expected_state:raise AssertionError("batched arbitration did not reach terminal state")
            if int(self.view(c.functions.arbReqState(item["id"],int(item["mode"]))))!=2:
                raise AssertionError("arbitration request did not reach Resolved")
            self._apply_terminal_audit(d,adjudicated)
            for key,value in d.get("ait_entries",[]):
                if self.view(c.functions.AIT(key))!=value:raise AssertionError("batched AIT mismatch")
            d["proof_queued"]=False;d["proof_submitted"]=True
        return len(batch)

    def flush_arbitration_proofs(self,accounts=None,force=False):

        if not self.pending_arbitration:return 0
        now=max(self.timestamp(),self.epoch+math.ceil(self.net.now));interval=self.config["gssc_block_interval_s"]
        selected=[];remaining=[]
        for item in self.pending_arbitration:
            tx=item["deal"]["tx"];touch={tx.sender,tx.receiver}
            urgent=False
            conflict=accounts is not None and bool(touch.intersection(accounts))
            if force or urgent or conflict:selected.append(item)
            else:remaining.append(item)
        if not selected:return 0
        groups={}
        for item in selected:groups.setdefault(item["asset"],[]).append(item)
        batch_size=int(self.config.get("gssc_arbitration_batch_size",32));submitted=0
        for asset,items in groups.items():
            c=items[0]["c"]
            for start in range(0,len(items),batch_size):
                batch=items[start:start+batch_size]
                saved_tx=self.net.service_tx
                self.net.service_tx=batch[0]["deal"]["tx"].id
                try:submitted+=self._submit_ballot_batch(c,batch)
                finally:self.net.service_tx=saved_tx
        self.pending_arbitration=remaining
        self.pending_arbitration_accounts={a for item in remaining for a in (item["deal"]["tx"].sender,item["deal"]["tx"].receiver)}
        return submitted
    def record_arbitration_cost(self,record):self.cost_records.append(record);self.arbitration_costs.write(json.dumps(record)+"\n")
    def finalize_epochs(self):
        self.flush_arbitration_proofs(force=True)
        roots={}
        for asset,entries in self.ait_entries.items():
            records=[r for r in self.local_records if r["asset"]==asset]
            all_entries=[entry for r in records for entry in r["entries"]]
            if not all_entries:continue
            def merkle(items):
                ordered=sorted(items,key=lambda item:item[0])
                if len({key for key,_ in ordered})!=len(ordered):raise AssertionError("duplicate AIT key")
                if not ordered:return self.w3.keccak(b"")
                leaves=[self.w3.keccak(key+value) for key,value in ordered]
                while len(leaves)>1:
                    if len(leaves)%2:leaves.append(leaves[-1])
                    leaves=[self.w3.keccak(leaves[i]+leaves[i+1]) for i in range(0,len(leaves),2)]
                return leaves[0]
            shard_records={s:[r for r in records if s in r["shards"]] for s in range(len(self.shards))}
            shard_entries={s:[entry for r in shard_records[s] for entry in r["entries"]] for s in range(len(self.shards))}
            shard_roots={}
            for shard in range(len(self.shards)):
                leader=self.consensus.leaders[shard].id
                shard_roots[shard]=self.net.compute(leader,"ait_shard_merkle_build",merkle,shard_entries[shard])
            aggregator=self.consensus.leaders[0].id
            def aggregate_root():
                return self.w3.keccak(b"".join(abi_encode(["uint256","bytes32"],[s,shard_roots[s]]) for s in range(len(self.shards))))
            root=self.net.compute(aggregator,"ait_epoch_root_aggregate",aggregate_root);c=self.contracts[asset]
            self.net.broadcast(aggregator,[n.id for shard in self.shards for n in shard],"AIT_EPOCH_PROPOSAL",
                dict(epoch=self.epoch_id,root=root.hex(),shard_roots={s:v.hex() for s,v in shard_roots.items()}),"cross_shard")
            digest=self.net.compute(aggregator,"epoch_digest",self.view,c.functions.epochDigest(self.epoch_id,root))
            signatures=[]
            for shard,nodes in enumerate(self.shards):
                votes=[]
                for node in nodes:
                    if node.malicious:continue
                    def validate():
                        if merkle(shard_entries[shard])!=shard_roots[shard]:return False
                        for r in shard_records[shard]:
                            if r["tx"] not in self.ledger.terminal:return False
                            body=r["certificates"][0]["proposal"]["body"]
                            if any(cert["proposal"]["body"]!=body for cert in r["certificates"]):return False
                            if body["commit"]!=(self.ledger.terminal[r["tx"]]=="COMMIT"):return False
                            if body["ait"]!=[(key.hex(),value.hex()) for key,value in r["entries"]]:return False
                        return True
                    if not self.net.compute(node.id,"epoch_state_verification",validate):raise AssertionError("invalid epoch data")
                    for r in records:
                        if shard in r["shards"]:
                            for cert in r["certificates"]:
                                if not self.consensus.verify_certificate(cert,node.id):raise AssertionError("invalid epoch certificate")
                    address=self.address["node:"+str(node.id)]
                    sig=self.net.compute(node.id,"epoch_certificate_sign",Account.sign_message,encode_defunct(primitive=digest),private_key=self.signing_keys[address])
                    votes.append(bytes(sig.signature))
                    self.net.send(node.id,aggregator,"AIT_EPOCH_VOTE",dict(epoch=self.epoch_id,root=root.hex(),signature=bytes(sig.signature).hex()),"cross_shard")
                    if len(votes)==7:break
                if len(votes)!=7:raise RuntimeError("epoch shard quorum unavailable")
                signatures.append(votes)
            self.net.drain()
            self.call(c,"finalizeEpoch",self.faucet,self.epoch_id,root,signatures)
            assert self.view(c.functions.epochRoot(self.epoch_id))==root
            for address,expected in self.expected_balances[asset].items():
                actual=self.view(c.functions.balances(address))
                assert actual==expected,(asset,address,"epoch balance",expected,actual)
            assert self.view(c.functions.penaltyReserve())==self.expected_reserve[asset]
            assert self.view(c.functions.rewardReserve())==self.expected_reward_reserve[asset]
            assert self.view(c.functions.totalPrincipal())==0,"principal must never enter GSSC"
            self.audit.write(json.dumps(dict(epoch=self.epoch_id,asset=asset,native_records=len(records),stage="native_epoch_certification",passed=True))+"\n")
            roots[asset]=root.hex()
        return roots
    def close(self):self.receipts.close();self.audit.close();self.arbitration_costs.close()
