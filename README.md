# pyemmy

This is to be a python counterpart of [emmy](https://github.com/xlab-si/emmy).

## Generate gRPC code

Execute:

```
python -m grpc_tools.protoc -I ./protobuf --python_out=. --grpc_python_out=. ./protobuf/msgs.proto
```
