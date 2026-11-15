"""Private HTTPS transport for the network-isolated website sign-in browser."""
import asyncio
import re
from contextlib import suppress

from .connectors.web import _public_socket

_TARGET = re.compile(rb"CONNECT ([a-zA-Z0-9.-]{1,253}):443 HTTP/1\.[01]")


def host_allowed(host, domains):
    return any(host == domain or host.endswith("." + domain) for domain in domains)


async def tunnel(left, right):
    async def copy(source, destination):
        while block := await source.read(65536):
            destination.write(block)
            await destination.drain()

    tasks = [asyncio.create_task(copy(left[0], right[1])), asyncio.create_task(copy(right[0], left[1]))]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def connect(reader, writer, domains):
    peer = None
    try:
        async with asyncio.timeout(12):
            header = await reader.readuntil(b"\r\n\r\n")
            match = _TARGET.fullmatch(header.split(b"\r\n", 1)[0])
            host = match[1].decode().lower() if match else ""
            if not host or not host_allowed(host, domains):
                writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return
            # DNS answers are validated and pinned by the same connector helper.
            # Run the bounded network connect off the application event loop.
            def dial():
                sock = _public_socket((host, 443), 6, None)
                sock.setblocking(False)
                return sock

            # Retain the result long enough to close the socket even if shutdown
            # cancels this tunnel while the resolver thread is still working.
            dialing = asyncio.create_task(asyncio.to_thread(dial))
            try:
                sock = await asyncio.shield(dialing)
            except BaseException:
                def discard(task):
                    with suppress(Exception):
                        task.result().close()
                dialing.add_done_callback(discard)
                raise
            try:
                peer = await asyncio.open_connection(sock=sock)
            except BaseException:
                sock.close()
                raise
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        await tunnel((reader, writer), peer)
    except Exception:
        pass  # Chromium renders its own network error; never log URLs or payloads.
    finally:
        if peer:
            peer[1].close()
        writer.close()
