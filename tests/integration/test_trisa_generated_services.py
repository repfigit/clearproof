"""Exercise generated RPC dispatch on an owned loopback-only test server."""

from concurrent.futures import ThreadPoolExecutor

import grpc
import grpc.experimental
import pytest

from src.protocol.bridges import trisa_api_pb2 as api
from src.protocol.bridges import trisa_api_pb2_grpc as services


@pytest.fixture
def unimplemented_trisa_server():
    # Synthetic dispatch test only; deployed TRISA endpoints require mTLS.
    with ThreadPoolExecutor(max_workers=2) as workers:
        server = grpc.server(workers)
        services.add_TRISANetworkServicer_to_server(services.TRISANetworkServicer(), server)
        services.add_TRISAHealthServicer_to_server(services.TRISAHealthServicer(), server)
        port = server.add_insecure_port("127.0.0.1:0")
        assert port > 0
        server.start()
        try:
            yield f"127.0.0.1:{port}"
        finally:
            assert server.stop(0).wait(timeout=5)


@pytest.mark.parametrize("client_style", ["stub", "experimental"])
@pytest.mark.parametrize("method", ["Transfer", "TransferStream", "ConfirmAddress", "KeyExchange", "Status"])
def test_generated_default_handlers_return_unimplemented(unimplemented_trisa_server, client_style, method):
    target = unimplemented_trisa_server
    requests = {
        "Transfer": api.SecureEnvelope(id="synthetic-dispatch", sealed=True),
        "TransferStream": iter([api.SecureEnvelope(id="synthetic-stream", sealed=True)]),
        "ConfirmAddress": api.Address(),
        "KeyExchange": api.SigningKey(),
        "Status": api.HealthCheck(attempts=1),
    }
    with grpc.insecure_channel(target) as channel:
        grpc.channel_ready_future(channel).result(timeout=5)
        if client_style == "stub":
            stub = services.TRISAHealthStub(channel) if method == "Status" else services.TRISANetworkStub(channel)
            call = getattr(stub, method)
            kwargs = {"timeout": 5}
        else:
            service = services.TRISAHealth if method == "Status" else services.TRISANetwork
            call = getattr(service, method)
            kwargs = {"target": target, "insecure": True, "timeout": 5}
        with pytest.raises(grpc.RpcError) as error:
            response = call(requests[method], **kwargs)
            if method == "TransferStream":
                list(response)
        assert error.value.code() == grpc.StatusCode.UNIMPLEMENTED
        assert error.value.details() == "Method not implemented!"
