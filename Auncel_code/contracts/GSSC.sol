// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.24;

/// Transaction-level repair of the manuscript GSSC monetary rules.
/// Evidence is authenticated on-chain conduct.
/// PYPBC remains off-chain; 
contract GSSCSettlement {
    enum State { None, Pending, Committed, Aborted }
    enum ArbReqState { None, Admitted, Resolved }
    struct Deal {
        address sender; address receiver; uint256 amount; uint256 partyBond;
        uint256 epoch; uint256 nonce; uint256 senderVersion; uint256 receiverVersion;
        uint256 responseDue; uint256 secretDue; uint256 ackDue; uint256 expires;
        bytes32 txHash; bytes32 secretHash; State state; bool accepted; bool responded;
        bool secretSubmitted; bool secretValid; bool disputed; uint8 mode; address requester;
        uint256 yes; uint256 no;
    }
    struct Ballot { address voter; bool support; }
    struct Terms {
        address receiver; uint256 nonce; uint256 epoch; bytes32 txHash;
        uint256 amount; uint256 partyBond; uint256 senderVersion; uint256 receiverVersion;
        uint256 responseDue; uint256 secretDue; uint256 ackDue; uint256 expires;
        bytes32 secretHash;
    }
    address public immutable owner;
    uint256 public immutable quorum;
    uint256 public immutable requestBond;
    uint256 public immutable arbiterBond;
    // C_gas is the measured gas cost of one arbitration participation.
    // It is an economic deduction, not a fixed work reward.
    uint256 public immutable gasCost;
    // Fig.5 R0: minimum gross reward for each honest winning arbitrator.
    uint256 public immutable minimumArbitrationReward;
    uint256 public immutable committeeSize;
    mapping(address=>bool) public member;
    mapping(address=>uint256) public balances;
    mapping(address=>uint256) public nonces;
    mapping(address=>uint256) public versions;
    mapping(address=>bytes32) public pendingByAccount;
    mapping(bytes32=>Deal) private deals;
    mapping(bytes32=>mapping(uint8=>ArbReqState)) public arbReqState;
    mapping(bytes32=>Ballot[]) private ballots;
    mapping(bytes32=>mapping(address=>bool)) public voted;
    mapping(bytes32=>bytes32) public arbitrationEvidenceHash;
    mapping(uint256=>mapping(address=>bool)) public shardMember;
    mapping(uint256=>bool) public shardRegistered;
    uint256 public registeredShards;
    mapping(address=>uint256) public lastRequestBlock;
    mapping(bytes32=>bytes32) public AIT;
    mapping(uint256=>bytes32) public epochRoot;
    mapping(uint256=>bool) public epochFinalized;
    uint256 public totalAvailable;
    uint256 public totalPrincipal;
    uint256 public totalPartyBonds;
    uint256 public totalArbiterBonds;
    uint256 public totalRequestBonds;
    uint256 public penaltyReserve;
    uint256 public rewardReserve;
    bool private withdrawing;
    event Transition(bytes32 indexed id, State state, uint8 mode);
    event Accounted(bytes32 indexed id,address indexed account,string reason,uint256 amount);
    event RequestRejected(bytes32 indexed id,address indexed requester,uint8 mode);
    event RewardPool(bytes32 indexed id,uint256 pool,uint256 winners,uint256 perWinner,uint256 remainder);
    event Registered(uint256 indexed epoch,bytes32 indexed id,address indexed sender,address receiver,bytes32 txHash);
    event StateUpdated(uint256 indexed epoch,bytes32 indexed id,address indexed account,bytes32 action,bytes32 aitKey);
    event EpochFinalized(uint256 indexed epoch,bytes32 root);

    constructor(address[] memory committee,uint256 q,uint256 reqBond,uint256 voteBond,uint256 measuredGasCost,uint256 minimumReward) {
        require(committee.length>=2 && committee.length<=64,"committee size");
        // q=f+1, where floor(2*(s-1)/3) < f < s and s is the
        // arbitration committee size.  The Python harness supplies the
        // configured f for the current committee size.
        require(q>2*(committee.length-1)/3+1 && q<=committee.length,"quorum");
        require(reqBond>0 && voteBond>0 && measuredGasCost>0 && minimumReward>measuredGasCost,"bond");
        owner=msg.sender; committeeSize=committee.length; quorum=q;
        requestBond=reqBond; arbiterBond=voteBond; gasCost=measuredGasCost;
        minimumArbitrationReward=minimumReward;
        for(uint256 i=0;i<committee.length;i++) {
            require(committee[i]!=address(0) && !member[committee[i]],"member");
            member[committee[i]]=true;
        }
    }
    function deposit() external payable {
        require(msg.value>0,"zero deposit");
        balances[msg.sender]+=msg.value; totalAvailable+=msg.value;
        emit Accounted(0,msg.sender,"deposit",msg.value);
    }
    function fundRewardReserve() external payable {
        require(msg.sender==owner && msg.value>0,"reward funding");
        rewardReserve+=msg.value;
        emit Accounted(0,msg.sender,"R0 reward reserve",msg.value);
    }
    function withdraw(uint256 amount) external {
        require(!withdrawing && amount>0,"withdrawal"); withdrawing=true;
        _debit(msg.sender,amount);
        (bool ok,)=payable(msg.sender).call{value:amount}("");require(ok,"transfer failed");
        withdrawing=false;
    }
    function txId(address sender,address receiver,uint256 nonce,uint256 epoch,bytes32 txHash) public pure returns(bytes32) {
        return keccak256(abi.encodePacked(sender,receiver,nonce,epoch,txHash));
    }
    function transactionState(bytes32 id) external view returns(State) { return deals[id].state; }
    function getDeal(bytes32 id) external view returns(Deal memory) { return deals[id]; }
    function getBallots(bytes32 id) external view returns(Ballot[] memory) { return ballots[id]; }
    function accounted() public view returns(uint256) {
        return totalAvailable+totalPrincipal+totalPartyBonds+totalArbiterBonds+
            totalRequestBonds+penaltyReserve+rewardReserve;
    }
    function registrationDigest(address sender,Terms calldata p) public view returns(bytes32) {
        bytes32 termsHash=keccak256(abi.encode(p.receiver,p.nonce,p.epoch,p.txHash,p.amount,
            p.partyBond,p.senderVersion,p.receiverVersion,p.responseDue,p.secretDue,p.ackDue,
            p.expires,p.secretHash));
        return keccak256(abi.encode(block.chainid,address(this),sender,termsHash));
    }
    function registerAndAccept(address sender,Terms calldata p,bytes calldata signature) external returns(bytes32 id) {
        require(sender!=address(0),"sender");
        require(msg.sender==p.receiver,"receiver");
        require(_recoverBallot(registrationDigest(sender,p),signature)==sender,"sender signature");
        id=_registerTransaction(sender,p);
        _accept(id,msg.sender);
    }
    function registerTransaction(Terms calldata p) public returns(bytes32 id) {
        return _registerTransaction(msg.sender,p);
    }
    function _registerTransaction(address sender,Terms calldata p) internal returns(bytes32 id) {
        id=txId(sender,p.receiver,p.nonce,p.epoch,p.txHash);
        Deal storage existing=deals[id];
        if(existing.state!=State.None) {
            require(existing.sender==sender && existing.receiver==p.receiver && existing.nonce==p.nonce &&
                existing.epoch==p.epoch && existing.txHash==p.txHash,"txID collision");
            return id; // exact duplicate registration is idempotent
        }
        require(!epochFinalized[p.epoch],"epoch closed");
        require(p.nonce==nonces[sender],"nonce");
        require(p.senderVersion==versions[sender] && p.receiverVersion==versions[p.receiver],"stale version");
        require(pendingByAccount[sender]==bytes32(0) && pendingByAccount[p.receiver]==bytes32(0),"account pending");
        require(p.receiver!=address(0) && p.receiver!=sender,"receiver");
        require(!member[sender] && !member[p.receiver],"party arbiter conflict");
        require(p.amount>0 && p.partyBond>0 && p.secretHash!=bytes32(0),"terms");
        require(block.timestamp<p.responseDue && p.responseDue<p.secretDue &&
            p.secretDue<p.ackDue && p.ackDue<p.expires,"deadlines");
        // Principal is a shard-native asset. Only collateral enters this contract.
        _debit(sender,p.partyBond);
        nonces[sender]++;
        Deal storage d=deals[id];d.sender=sender;d.receiver=p.receiver;
        pendingByAccount[sender]=id;pendingByAccount[p.receiver]=id;
        d.epoch=p.epoch;d.nonce=p.nonce;d.senderVersion=p.senderVersion;d.receiverVersion=p.receiverVersion;d.txHash=p.txHash;
        d.amount=p.amount;d.partyBond=p.partyBond;d.responseDue=p.responseDue;
        d.secretDue=p.secretDue;d.ackDue=p.ackDue;d.expires=p.expires;
        d.secretHash=p.secretHash;d.state=State.Pending;
        totalPartyBonds+=p.partyBond;
        emit Registered(p.epoch,id,sender,p.receiver,p.txHash);emit Transition(id,d.state,0);
    }
    function Balance(Terms calldata p) external returns(bytes32 id) { return _registerTransaction(msg.sender,p); }
    function accept(bytes32 id) external {
        _accept(id,msg.sender);
    }
    function _accept(bytes32 id,address receiver) internal {
        Deal storage d=deals[id];
        require(d.state==State.Pending && !d.accepted && receiver==d.receiver && block.timestamp<d.responseDue,"accept");
        require(versions[receiver]==d.receiverVersion,"stale receiver");
        _debit(receiver,d.partyBond);totalPartyBonds+=d.partyBond;d.accepted=true;
        emit Transition(id,d.state,0);
    }
    function respond(bytes32 id) external {
        Deal storage d=deals[id];
        require(d.state==State.Pending && d.accepted && msg.sender==d.receiver && !d.responded && block.timestamp<d.responseDue,"respond");
        d.responded=true;
    }
    function publishSecret(bytes32 id,bytes calldata secret) external {
        Deal storage d=deals[id];
        require(d.state==State.Pending && d.accepted && msg.sender==d.sender && d.responded &&
            !d.secretSubmitted && block.timestamp<d.secretDue,"publish");
        require(secret.length>0 && secret.length<=1024,"secret length");
        d.secretSubmitted=true;d.secretValid=keccak256(secret)==d.secretHash;
           }
    function completeNormal(bytes32 id,bytes calldata secret) external {
        Deal storage d=deals[id];
        require(d.state==State.Pending && d.accepted && !d.disputed && d.responded,"normal state");
        require(msg.sender==d.sender || msg.sender==d.receiver,"participant");
        require(!d.secretSubmitted && block.timestamp<d.secretDue,"normal deadline");
        require(secret.length>0 && secret.length<=1024 && keccak256(secret)==d.secretHash,"secret");
        d.secretSubmitted=true;d.secretValid=true;
        _settle(id,true,false);
    }
    function validEvidence(bytes32 id,uint8 mode,bytes calldata evidence) public view returns(bool) {
        Deal storage d=deals[id];
        if(mode==1) return evidence.length==0 &&
            ((!d.responded && block.timestamp>=d.responseDue) ||
             (d.secretSubmitted && d.secretValid && block.timestamp>=d.ackDue));
        if(mode==2) return evidence.length==0 && d.secretSubmitted && !d.secretValid;
        if(mode==3) return d.responded && !d.secretSubmitted && block.timestamp>=d.secretDue &&
            keccak256(evidence)==d.secretHash;
        return false;
    }
    function admitArbitrationRequest(bytes32 id,uint8 mode) external {
        Deal storage d=deals[id];
        require(d.state!=State.None,"unknown tx");
        require(d.state==State.Pending && d.accepted && !d.disputed && block.timestamp<d.expires,"request state");
        require(msg.sender==d.sender || msg.sender==d.receiver,"participant");
        require(mode>=1 && mode<=3,"request type");
        require(arbReqState[id][mode]==ArbReqState.None,"request exists");
        bool permitted;
        if(mode==1) permitted=(!d.responded && block.timestamp>=d.responseDue) ||
            (d.secretSubmitted && d.secretValid && block.timestamp>=d.ackDue);
        else if(mode==2) permitted=d.secretSubmitted && !d.secretValid;
        else permitted=d.responded && !d.secretSubmitted && block.timestamp>=d.secretDue;
        require(permitted,"request type state");
        arbReqState[id][mode]=ArbReqState.Admitted;
    }
    function request(bytes32 id,uint8 mode,bytes calldata evidence) external payable returns(bool) {
        Deal storage d=deals[id];
        require(d.state==State.Pending && d.accepted && !d.disputed && block.timestamp<d.expires,"request state");
        require(msg.sender==d.sender || msg.sender==d.receiver,"participant");
        require(msg.value==requestBond && evidence.length<=1024 && mode>=1 && mode<=3,"request bounds");
        require(arbReqState[id][mode]==ArbReqState.Admitted,"request not admitted");
        require(lastRequestBlock[msg.sender]!=block.number,"rate limit");lastRequestBlock[msg.sender]=block.number;
        bool side=(mode==1?msg.sender==d.sender:msg.sender==d.receiver);
        if(!side || !validEvidence(id,mode,evidence)) {
            penaltyReserve+=msg.value;emit RequestRejected(id,msg.sender,mode);return false;
        }
        d.mode=mode;d.requester=msg.sender;d.disputed=true;totalRequestBonds+=msg.value;
        arbitrationEvidenceHash[id]=keccak256(evidence);
        emit Transition(id,d.state,mode);return true;
    }

    function submitArbitrationProof(bytes32 id,uint8 mode,bytes calldata evidence,
        bool[] calldata support,bytes[] calldata signatures) external payable {
        Deal storage d=deals[id];
        require(d.state==State.Pending && d.accepted && !d.disputed && block.timestamp<d.expires,"request state");
        require(msg.sender==d.sender || msg.sender==d.receiver,"participant");
        require(msg.value==requestBond && evidence.length<=1024 && mode>=1 && mode<=3,"request bounds");
        require(arbReqState[id][mode]==ArbReqState.Admitted,"request not admitted");
        require(lastRequestBlock[msg.sender]!=block.number,"rate limit");lastRequestBlock[msg.sender]=block.number;
        bool side=(mode==1?msg.sender==d.sender:msg.sender==d.receiver);
        require(side && validEvidence(id,mode,evidence),"invalid evidence");
        d.mode=mode;d.requester=msg.sender;d.disputed=true;totalRequestBonds+=msg.value;
        arbitrationEvidenceHash[id]=keccak256(evidence);
        emit Transition(id,d.state,mode);
        _submitBallots(id,support,signatures,false);
    }
    function makeDecision(bytes32 id,bool support) external {
        Deal storage d=deals[id];
        require(d.state==State.Pending && d.disputed,"vote state");
        require(arbReqState[id][d.mode]==ArbReqState.Admitted,"request not admitted");
        require(member[msg.sender] && !voted[id][msg.sender],"voter");
        voted[id][msg.sender]=true;ballots[id].push(Ballot(msg.sender,support));
        if(support) d.yes++; else d.no++;
    }
    function ballotDigest(bytes32 id,bool support) public view returns(bytes32) {
        Deal storage d=deals[id];
        return ballotDigestFor(id,d.mode,arbitrationEvidenceHash[id],support);
    }
    function ballotDigestFor(bytes32 id,uint8 mode,bytes32 evidenceHash,bool support) public view returns(bytes32) {
        Deal storage d=deals[id];
        return keccak256(abi.encode(block.chainid,address(this),d.epoch,id,mode,
            evidenceHash,uint256(0),support));
    }
    // One authenticated certificate, followed by atomic threshold settlement.
    // Every included signer is checked; the collector cannot invent votes.
    function submitBallots(bytes32 id,bool[] calldata support,bytes[] calldata signatures) external {
        _submitBallots(id,support,signatures,false);
    }

      function submitBallotsBatch(bytes32[] calldata ids,bool[][] calldata supportSets,
        bytes[][] calldata signatures) external {
        require(msg.sender==owner,"batch caller");
        require(ids.length>0 && ids.length<=64 && supportSets.length==ids.length &&
            signatures.length==ids.length,"batch size");
        for(uint256 i=0;i<ids.length;i++) {
            _submitBallots(ids[i],supportSets[i],signatures[i],true);
        }
    }

    function _submitBallots(bytes32 id,bool[] calldata support,bytes[] calldata signatures,
        bool ownerBatch) internal {
        Deal storage d=deals[id];
        require(d.state==State.Pending && d.disputed,"vote state");
        require(arbReqState[id][d.mode]==ArbReqState.Admitted,"request not admitted");
        require(support.length==signatures.length && support.length<=committeeSize,"certificate size");
        for(uint256 i=0;i<support.length;i++) {
            address signer=_recoverBallot(ballotDigest(id,support[i]),signatures[i]);
            require(signer!=address(0) && member[signer] && !voted[id][signer],"certificate signer");
            voted[id][signer]=true;ballots[id].push(Ballot(signer,support[i]));
            if(support[i]) d.yes++; else d.no++;
        }
        if(d.yes>=quorum) _arbitrate(id,d.mode);
        else {
                      require(msg.sender==d.requester || (ownerBatch && msg.sender==owner),"unresolved requester");
        }
    }
    function _recoverBallot(bytes32 ballot,bytes calldata sig) internal pure returns(address) {
        require(sig.length==65,"signature length");
        bytes32 r;bytes32 s;uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset,32))
            v := byte(0,calldataload(add(sig.offset,64)))
        }
        require(uint256(s)<=0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 && (v==27 || v==28),"signature canonical");
        bytes32 digest=keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",ballot));
        return ecrecover(digest,v,r,s);
    }
    function arb_1(bytes32 id) external { _arbitrate(id,1); }
    function arb_2(bytes32 id) external { _arbitrate(id,2); }
    function abr_3(bytes32 id) external { _arbitrate(id,3); }
    function _arbitrate(bytes32 id,uint8 mode) internal {
        Deal storage d=deals[id];
        require(d.state==State.Pending && d.disputed && d.mode==mode && d.yes>=quorum &&
            arbReqState[id][mode]==ArbReqState.Admitted,"arbitration");
        _settle(id,mode==3,true);
        arbReqState[id][mode]=ArbReqState.Resolved;
    }
    function closeUnresolved(bytes32 id) external {
        Deal storage d=deals[id];
        require(d.state==State.Pending && d.disputed && msg.sender==d.requester,"unresolved state");
        require(arbReqState[id][d.mode]==ArbReqState.Admitted,"request not admitted");
        require(d.yes<quorum,"quorum reached");
        _settle(id,false,false);
        arbReqState[id][d.mode]=ArbReqState.Resolved;
    }
    function expire(bytes32 id) public {
        Deal storage d=deals[id];
        if(d.state==State.Committed || d.state==State.Aborted) return;
        require(d.state==State.Pending && !d.disputed && block.timestamp>=d.expires,"expiry");
        _settle(id,false,false);
    }
    function expireBatch(bytes32[] calldata ids) external {
        require(ids.length>0 && ids.length<=32,"batch size");
        for(uint256 i=0;i<ids.length;i++) expire(ids[i]);
    }
    function _settle(bytes32 id,bool commit,bool adjudicated) internal {
        Deal storage d=deals[id];bool accepted=d.accepted;
        require(d.state==State.Pending,"terminal");
        require(versions[d.sender]==d.senderVersion && versions[d.receiver]==d.receiverVersion,"stale finalization");
        d.state=commit?State.Committed:State.Aborted;versions[d.sender]++;versions[d.receiver]++;
        pendingByAccount[d.sender]=bytes32(0);pendingByAccount[d.receiver]=bytes32(0);
        emit Transition(id,d.state,d.mode);
         totalPartyBonds-=d.partyBond*(accepted?2:1);
        uint256 pool=0;
        if(adjudicated) {
            address honestParty=d.mode==1?d.sender:d.receiver;
            _credit(id,honestParty,d.partyBond,"party bond return");pool=d.partyBond;
            emit Accounted(id,d.mode==1?d.receiver:d.sender,"party bond slash",d.partyBond);
        } else {
            _credit(id,d.sender,d.partyBond,"party bond return");
            if(accepted) _credit(id,d.receiver,d.partyBond,"party bond return");
        }
        Ballot[] storage list=ballots[id];uint256 winners=0;
        if(adjudicated) {
            for(uint256 i=0;i<list.length;i++) if(list[i].support) winners++;
            require(winners>=quorum,"reward quorum");
            uint256 baseReward=minimumArbitrationReward*winners;
            require(rewardReserve>=baseReward,"R0 reserve");
            rewardReserve-=baseReward;pool+=baseReward;
             uint256 gasPool=0;
            for(uint256 i=0;i<list.length;i++) {
                _debit(list[i].voter,gasCost);gasPool+=gasCost;
                if(!list[i].support) {
                    _debit(list[i].voter,arbiterBond);pool+=arbiterBond;
                    emit Accounted(id,list[i].voter,"arbiter bond slash",arbiterBond);
                }
            }
            penaltyReserve+=gasPool;
            uint256 each=pool/winners;uint256 remainder=pool%winners;
            for(uint256 i=0;i<list.length;i++) if(list[i].support) _credit(id,list[i].voter,each,"honest pool reward net C_gas");
            penaltyReserve+=remainder;emit RewardPool(id,pool,winners,each,remainder);
        }
        if(d.requester!=address(0)) {
            totalRequestBonds-=requestBond;_credit(id,d.requester,requestBond,"request bond return");
        }
        _recordAIT(d.epoch,id,d.sender,commit?keccak256("DEBIT_COMMIT"):keccak256("REFUND_ABORT"));
        _recordAIT(d.epoch,id,d.receiver,commit?keccak256("CREDIT_COMMIT"):keccak256("NO_CREDIT_ABORT"));
    }
    function _recordAIT(uint256 epoch,bytes32 id,address account,bytes32 action) internal {
        bytes32 key=keccak256(abi.encode(epoch,id,account));
        require(AIT[key]==bytes32(0),"AIT duplicate");AIT[key]=keccak256(abi.encode(action));
        emit StateUpdated(epoch,id,account,action,key);
    }
    function registerShard(uint256 shard,address[] calldata nodes) external {
        require(msg.sender==owner && shard<committeeSize && !shardRegistered[shard],"shard registration");
        require(nodes.length==10,"shard size");
        for(uint256 i=0;i<nodes.length;i++) {
            require(nodes[i]!=address(0) && !shardMember[shard][nodes[i]],"duplicate member");
            shardMember[shard][nodes[i]]=true;
        }
        shardRegistered[shard]=true;registeredShards++;
    }
    function epochDigest(uint256 epoch,bytes32 root) public view returns(bytes32) {
        return keccak256(abi.encode(block.chainid,address(this),epoch,root,keccak256("NATIVE_AIT_EPOCH")));
    }
    function _verifyEpochShard(uint256 shard,bytes32 digest,bytes[] calldata signatures) internal view {
        require(signatures.length==7,"epoch quorum");
        address[] memory seen=new address[](7);
        for(uint256 i=0;i<7;i++) {
            address signer=_recoverBallot(digest,signatures[i]);
            require(shardMember[shard][signer],"epoch signer");
            for(uint256 j=0;j<i;j++) require(seen[j]!=signer,"duplicate epoch vote");
            seen[i]=signer;
        }
    }
    function finalizeEpoch(uint256 epoch,bytes32 root,bytes[][] calldata signatures) external {
        require(registeredShards==committeeSize && signatures.length==committeeSize,"epoch shards");
        require(!epochFinalized[epoch] && root!=bytes32(0),"epoch root");
        bytes32 digest=epochDigest(epoch,root);
        for(uint256 shard=0;shard<committeeSize;shard++) _verifyEpochShard(shard,digest,signatures[shard]);
        epochFinalized[epoch]=true;epochRoot[epoch]=root;emit EpochFinalized(epoch,root);
    }
    function _debit(address account,uint256 amount) internal {
        require(balances[account]>=amount,"insufficient available");
        balances[account]-=amount;totalAvailable-=amount;
    }
    function _credit(bytes32 id,address account,uint256 amount,string memory reason) internal {
        balances[account]+=amount;totalAvailable+=amount;emit Accounted(id,account,reason,amount);
    }
}
