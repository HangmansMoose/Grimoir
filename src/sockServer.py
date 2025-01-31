#!/usr/bin/env python
import asyncio
import ssl
import pathlib
from websockets.asyncio.server import serve

async def hello(websocket):
    name = await websocket.recv()
    print(f"<<< {name}")

    greeting = f"Hello {name}!"

    await websocket.send(greeting)

    print(f">>> {greeting}")

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

localhost_pem = pathlib.Path(__file__).with_name("cert.pem")

ssl_context.load_cert_chain(localhost_pem)

async def main():
    async with serve(hello, "localhost", 9785, ssl=ssl_context):
        await asyncio.get_running_loop().create_future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())


