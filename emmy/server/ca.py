from Crypto.Util import number
import grpc
import time
from emmy.protobuf import msgs_pb2
from emmy.protobuf import msgs_pb2_grpc
from emmy.common.config import get_pseudonymsys_group
from emmy.proofs.schnorrprotocol import SchnorrVerifier
from concurrent import futures
from blockstack_client.actions import cli_lookup
import argparse

class ProtocolServicer(msgs_pb2_grpc.ProtocolServicer):
    def __init__(self):
        p, q, g = get_pseudonymsys_group()
        self.verifier = SchnorrVerifier(p, q, g)

    def Run(self, request_iterator, context):
        msg_num = 0
        for m in request_iterator:
            if msg_num == 0:
                fields = m.ListFields()
                proof_random_data = fields[1][1].ListFields()
                x = proof_random_data[0][1]
                a = proof_random_data[1][1]
                b = proof_random_data[2][1]
                x = number.bytes_to_long(x)
                a = number.bytes_to_long(a)
                b = number.bytes_to_long(b)
               
                fqu = proof_random_data[3][1]
                args = argparse.Namespace()
                args.name = fqu
                blockchain_record = cli_lookup(args)
                pubKey = blockchain_record["profile"]["masterPubKey"] 
                if pubKey != b:
                    return None
                
                challenge = self.verifier.get_challenge(x, a, b)
                ch = msgs_pb2.BigInt
                ch.X1 = challenge
                msg = msgs_pb2.Message(bigint=ch)
                return msg

_ONE_DAY_IN_SECONDS = 60 * 60 * 24


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    msgs_pb2_grpc.add_ProtocolServicer_to_server(
        ProtocolServicer(), server)
    port = "7007"
    server.add_insecure_port('[::]:%s' % port)

    server.start()
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop(0) 

