from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path


BINDINGS_DIR = Path(__file__).resolve().parent / "trafficlens_wit"
if str(BINDINGS_DIR) not in sys.path:
    sys.path.insert(0, str(BINDINGS_DIR))

from componentize_py_types import Ok
import poll_loop
from poll_loop import PollLoop, Sink, Stream
from trafficlens_core import analyze_pcap_bytes
from wit_world import exports
from wit_world.imports.types import (
    Fields,
    IncomingRequest,
    Method_Get,
    Method_Post,
    OutgoingResponse,
    ResponseOutparam,
)


class IncomingHandler(exports.IncomingHandler):
    """Expose TrafficLens packet analysis as a WASI HTTP component."""

    def handle(self, request: IncomingRequest, response_out: ResponseOutparam) -> None:
        loop = PollLoop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(handle_async(request, response_out))


async def handle_async(request: IncomingRequest, response_out: ResponseOutparam) -> None:
    method = request.method()
    path = request.path_with_query() or "/"
    route = path.split("?", 1)[0]

    try:
        if isinstance(method, Method_Get) and route == "/health":
            await send_json_response(response_out, 200, {"status": "ok"})
            return

        if isinstance(method, Method_Get) and route == "/":
            await send_json_response(
                response_out,
                200,
                {
                    "service": "TrafficLens",
                    "endpoints": {
                        "GET /health": "Basic liveness check.",
                        "POST /analyze": "Send raw PCAP bytes in the request body to receive packet summaries.",
                    },
                },
            )
            return

        if isinstance(method, Method_Post) and route == "/analyze":
            request_body = await read_request_body(request)
            packets = analyze_pcap_bytes(request_body)
            await send_json_response(
                response_out,
                200,
                {
                    "packet_count": len(packets),
                    "packets": packets[:200],
                },
            )
            return

        await send_json_response(
            response_out,
            404,
            {
                "error": "not_found",
                "message": f"No route matches {route!r}.",
            },
        )
    except ValueError as exc:
        await send_json_response(
            response_out,
            400,
            {
                "error": "invalid_pcap",
                "message": str(exc),
            },
        )
    except Exception as exc:
        await send_json_response(
            response_out,
            500,
            {
                "error": "internal_error",
                "message": str(exc),
            },
        )


async def read_request_body(request: IncomingRequest) -> bytes:
    stream = Stream(request.consume())
    chunks: list[bytes] = []

    while True:
        chunk = await stream.next()
        if chunk is None:
            break
        chunks.append(chunk)

    return b"".join(chunks)


async def send_json_response(
    response_out: ResponseOutparam, status_code: int, payload: dict[str, object]
) -> None:
    body_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    response = OutgoingResponse(
        Fields.from_list(
            [
                ("content-type", b"application/json"),
                ("content-length", str(len(body_bytes)).encode("utf-8")),
            ]
        )
    )
    response.set_status_code(status_code)
    ResponseOutparam.set(response_out, Ok(response))

    sink = Sink(response.body())
    if body_bytes:
        await sink.send(body_bytes)
    sink.close()
