# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

import msgs_pb2 as msgs__pb2


class ProtocolStub(object):
  """A generic service
  """

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.Run = channel.stream_stream(
        '/protobuf.Protocol/Run',
        request_serializer=msgs__pb2.Message.SerializeToString,
        response_deserializer=msgs__pb2.Message.FromString,
        )


class ProtocolServicer(object):
  """A generic service
  """

  def Run(self, request_iterator, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_ProtocolServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'Run': grpc.stream_stream_rpc_method_handler(
          servicer.Run,
          request_deserializer=msgs__pb2.Message.FromString,
          response_serializer=msgs__pb2.Message.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'protobuf.Protocol', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))