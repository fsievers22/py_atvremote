from atvremote import atvremote
from atvremote import messages
import logging
import asyncio
import sys

hostname = "localhost"

def receive_from_atv(msg: messages.CommandMessage):
    logging.info(msg)

async def main() -> int:
    logging.basicConfig(level=logging.DEBUG)
    atv_remote = atvremote.ATVRemote(hostname, receive_from_atv)
    await atv_remote.pair()
    print("paired")
    await atv_remote.connect()
    print("connected")
    remote_task = atv_remote.listen_forever()
    await asyncio.sleep(3)
    await atv_remote.key_press("KEYCODE_DPAD_UP")
    await remote_task
    return 0




if __name__ == '__main__':
    sys.exit(asyncio.run(main())) 