"""Minimal interactive peer over the plaintext development transport.

Run one instance per device (or several on one machine with different ports):

    python examples/basic_peer.py --name laptop-a
    python examples/basic_peer.py --name laptop-b --connect 192.168.1.20:47800

Instances with the same --app-id on the same LAN find each other via mDNS and
connect automatically. Type a line and press Enter to broadcast it to all
connected peers. Events are printed as JSON lines. Ctrl+C or EOF quits.

WARNING: this demo uses allow_insecure_transport=True: traffic is NOT encrypted
or authenticated and pairing, groups and sync are unavailable. Use only on a
trusted network for development.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys

from universal_p2p_sync import AsyncSyncNode, Event


def emit(record: dict) -> None:
    print(json.dumps(record), flush=True)


def parse_hostport(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError("expected HOST:PORT")
    return host, int(port)


async def main(args: argparse.Namespace) -> int:
    node = AsyncSyncNode(
        app_id=args.app_id,
        user_id=args.user,
        device_name=args.name,
        listen_host=args.host,
        listen_port=args.port,
        enable_discovery=not args.no_discovery,
        allow_insecure_transport=True,  # Milestone 1 has no encryption yet
    )

    def print_event(event: Event) -> None:
        emit({"event": event.name, **{k: v for k, v in event.data.items()}})

    async def echo_back(event: Event) -> None:
        if "echo" not in event["payload"]:
            await node.send_message(event["device_id"], {"echo": event["payload"]})

    node.on("*", print_event)
    if args.echo:
        node.on("message_received", echo_back)

    await node.start()
    host, port = node.listen_address  # type: ignore[misc]
    emit({"event": "listening", "host": host, "port": port, "device_id": node.device_id})

    for target in args.connect:
        node.add_peer_address(*target)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # Windows
            pass

    async def read_stdin() -> None:
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            text = line.strip()
            if text:
                sent = await node.broadcast_message({"text": text, "from": args.name})
                emit({"event": "sent", "peers": sent})
        stop.set()

    stdin_task = asyncio.create_task(read_stdin())
    try:
        await stop.wait()
    finally:
        stdin_task.cancel()
        await node.stop()
        emit({"event": "stopped"})
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--app-id", default="demo")
    parser.add_argument("--name", default="basic-peer")
    parser.add_argument("--user", default="user_001")
    parser.add_argument("--host", default="0.0.0.0", help="listen address")
    parser.add_argument("--port", type=int, default=47800, help="listen port (0 = random)")
    parser.add_argument("--connect", type=parse_hostport, action="append", default=[])
    parser.add_argument("--no-discovery", action="store_true")
    parser.add_argument("--echo", action="store_true", help="echo received messages back")
    parser.add_argument("-v", "--verbose", action="store_true")
    ns = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO if ns.verbose else logging.WARNING,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        sys.exit(asyncio.run(main(ns)))
    except KeyboardInterrupt:
        sys.exit(130)
