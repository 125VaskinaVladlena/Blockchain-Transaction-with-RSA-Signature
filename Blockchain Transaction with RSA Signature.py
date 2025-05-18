import json
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class TransactionInput:
    def __init__(self, txid, output_index):
        self.txid = txid        
        self.output_index = output_index  

    def to_dict(self):
        return {'txid': self.txid, 'output_index': self.output_index}

class TransactionOutput:
    def __init__(self, address, amount):
        self.address = address
        self.amount = amount

    def to_dict(self):
        return {'address': self.address, 'amount': self.amount}

class Transaction:
    def __init__(self, inputs, outputs):
        self.inputs = inputs       
        self.outputs = outputs     
        self.signature = None      
        self.txid = None           

    def to_dict(self, include_signature=False):
        data = {
            'inputs': [inp.to_dict() for inp in self.inputs],
            'outputs': [out.to_dict() for out in self.outputs]
        }
        if include_signature and self.signature:
            data['signature'] = self.signature.hex()
        return data

    def serialize(self, include_signature=False):
        return json.dumps(self.to_dict(include_signature), sort_keys=True).encode()

    def hash(self):
        h = sha256()
        h.update(self.serialize())
        return h.hexdigest()

    def sign(self, private_key):
        h = SHA256.new(self.serialize())
        signer = pkcs1_15.new(private_key)
        self.signature = signer.sign(h)
        self.txid = self.hash()

    def verify_signature(self, public_key):
        if not self.signature:
            return False
        h = SHA256.new(self.serialize())
        verifier = pkcs1_15.new(public_key)
        try:
            verifier.verify(h, self.signature)
            return True
        except (ValueError, TypeError):
            return False

if __name__ == '__main__':
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()

    inputs = [TransactionInput(txid="abcd1234", output_index=0)]
    outputs = [TransactionOutput(address="recipient_address", amount=10)]

    tx = Transaction(inputs, outputs)
    tx.sign(private_key)
    print("Transaction ID:", tx.txid)
    print("Signature valid:", tx.verify_signature(public_key))
    print("Transaction JSON:", tx.to_dict(include_signature=True))