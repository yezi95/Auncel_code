import hashlib
from dataclasses import dataclass, field
from Crypto.Signature import eddsa

def seed_for(seed, label):
    return int.from_bytes(hashlib.sha256((str(seed)+":"+str(label)).encode()).digest(), "big")

@dataclass
class Node:
    id: int
    shard: int
    malicious: bool
    seed: int
    accounting: bool = False
    role: str = "shard_verifier"
    key: object = field(init=False, repr=False)

    def __post_init__(self):
        self.key=eddsa.import_private_key(seed_for(self.seed,"node:"+str(self.id)).to_bytes(32,"big"))

    def sign(self, payload):
        return eddsa.new(self.key,"rfc8032").sign(payload)

    def verify(self, payload, signature):
        try:
            eddsa.new(self.key.public_key(),"rfc8032").verify(payload,signature)
            return True
        except (ValueError,TypeError):
            return False

    def record(self):
        return dict(id=self.id,shard=self.shard,malicious=self.malicious,
                    accounting=self.accounting,role=self.role,
                    public_key=self.key.public_key().export_key(format="raw").hex())
