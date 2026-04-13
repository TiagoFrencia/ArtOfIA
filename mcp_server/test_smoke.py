"""Smoke test — validates tool functions end-to-end."""
import asyncio
from app.tools import ping, port_scan
from app.schemas import PingInput, PortScanInput


async def main() -> None:
    r1 = await ping(PingInput(message="healthcheck"))
    print(r1.model_dump_json(indent=2))

    r2 = await port_scan(PortScanInput(target="127.0.0.1", ports="135", timeout=1.0))
    print(r2.model_dump_json(indent=2))


asyncio.run(main())
