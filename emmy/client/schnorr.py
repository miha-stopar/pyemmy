from Crypto.Util import number
import grpc
import uuid
from emmy.protobuf import msgs_pb2
from emmy.protobuf import msgs_pb2_grpc
from emmy.proofs.schnorrprotocol import SchnorrProver
from emmy.common.config import get_pseudonymsys_group, get_pseudonymsys_user_secret

class Msgs():
    def __init__(self):
        secret = get_pseudonymsys_user_secret()
        p, q, g = get_pseudonymsys_group()
        self.secret = secret
        self.prover = SchnorrProver(secret, None, p, q, g)
        self.client_id = uuid.uuid4().int & ((1<<31)-1)
        self.challenge = None
        self.msg_num = 0

    def __iter__(self):
        return self
    
    def _proof_random_data(self):
        x = self.prover.get_proof_random_data(self.secret, self.prover.sgroup.g)
        b = self.prover.sgroup.exponentiate(self.prover.sgroup.g, self.secret)

        x_bytes = number.long_to_bytes(x)
        g_bytes = number.long_to_bytes(self.prover.sgroup.g)
        b_bytes = number.long_to_bytes(b)
        schema_type = msgs_pb2.SchemaType.Value("SCHNORR")
        variant = msgs_pb2.SchemaVariant.Value("SIGMA")
        data = msgs_pb2.SchnorrProofRandomData()
        data.A = g_bytes
        data.B = b_bytes
        data.X = x_bytes

        msg = msgs_pb2.Message(clientId=self.client_id, schema=schema_type, 
                           schema_variant=variant, schnorr_proof_random_data=data)
        return msg
    
    def _proof_data(self):
        proof_data = self.prover.get_proof_data(self.challenge)
        proof_data = number.long_to_bytes(proof_data)
        data = msgs_pb2.SchnorrProofData()
        data.Z = proof_data
        msg = msgs_pb2.Message(schnorr_proof_data=data)
        return msg

    def next(self):
        if self.msg_num == 0:
            msg = self._proof_random_data()
            self.msg_num += 1
            return msg
        elif self.msg_num == 1:
            msg = self._proof_data()
            self.msg_num += 1
            return msg
        else:
            raise StopIteration()
            

def run():
    endpoint = "localhost:7007"
    channel = grpc.insecure_channel(endpoint)
    stub = msgs_pb2_grpc.ProtocolStub(channel)
    
    s = Msgs()
    for r in stub.Run(s):
        pd = r.ListFields()[0][1]
        x = pd.ListFields()[0][1]
        x = number.bytes_to_long(x)
        s.challenge = x

    
    
