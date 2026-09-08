"""Check generated TRISA wire compatibility across protobuf runtime backends."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from src.protocol.bridges import trisa_api_pb2 as api
from src.protocol.bridges import trisa_errors_pb2 as errors


@pytest.mark.parametrize("backend", ["python", "upb"])
def test_generated_trisa_wire_compatibility(backend):
    envelope = api.SecureEnvelope(
        id="synthetic-runtime-vector",
        payload=b"synthetic-encrypted-payload",
        sealed=True,
        transfer_state=api.REJECTED,
        error=errors.Error(code=errors.Error.UNKNOWN_IDENTITY, message="synthetic rejection", retry=False),
    )
    # Unknown field 100 (varint 7) must survive a relay using either runtime.
    wire = envelope.SerializeToString(deterministic=True) + bytes.fromhex("a00607")
    script = r'''
import json
import sys
from google.protobuf.internal import api_implementation
from src.protocol.bridges import trisa_api_pb2 as api
from src.protocol.bridges import trisa_errors_pb2 as errors
from src.protocol.bridges import trisa_errors_pb2_grpc

assert api_implementation.Type() == sys.argv[1]
envelope = api.SecureEnvelope.FromString(bytes.fromhex(sys.argv[2]))
assert envelope.id == "synthetic-runtime-vector"
assert envelope.payload == b"synthetic-encrypted-payload"
assert envelope.sealed and envelope.transfer_state == api.REJECTED
assert envelope.error.code == errors.Error.UNKNOWN_IDENTITY
assert errors.Error.UNKOWN_IDENTITY == errors.Error.UNKNOWN_IDENTITY
assert errors.Error.BVRC002 == errors.Error.UNAVAILABLE
assert errors.Error.Code.Name(52) == "UNKNOWN_IDENTITY"
address = api.Address(key_token=api.KeyTokenQuery(token=b"synthetic-token"))
assert address.WhichOneof("confirmation_details") == "key_token"
address.on_chain.CopyFrom(api.OnChainQuery(amount=1.0))
assert address.WhichOneof("confirmation_details") == "on_chain"
assert not address.HasField("key_token")
assert api.Address.FromString(address.SerializeToString()) == address
methods = api.DESCRIPTOR.services_by_name["TRISANetwork"].methods_by_name
assert methods["TransferStream"].client_streaming and methods["TransferStream"].server_streaming
assert methods["Transfer"].input_type.full_name == "trisa.api.v1beta1.SecureEnvelope"
assert not trisa_errors_pb2_grpc._version_not_supported
print(json.dumps({"wire": envelope.SerializeToString(deterministic=True).hex()}))
'''
    result = subprocess.run(
        [sys.executable, "-c", script, backend, wire.hex()],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION": backend},
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert json.loads(result.stdout) == {"wire": wire.hex()}
