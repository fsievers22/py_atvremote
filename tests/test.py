from py_atvremote import py_atvremote
from py_atvremote import messages
import logging
import asyncio
import sys

hostname = "localhost"
atv_remote: py_atvremote.ATVRemote = None
activiy = None

def receive_from_atv(msg: messages.CommandMessage):
    logging.info(msg)

async def main() -> int:
    logging.basicConfig(level=logging.DEBUG)
    global atv_remote 
    atv_remote = py_atvremote.ATVRemote(hostname)
    #await atv_remote.start_pairing()
    #code = input("Code: ")
    #await atv_remote.finish_pairing(code=code)
    #print("paired")
    await atv_remote.establish_connection(update_callback=update)
    #remote_task = atv_remote.listen_forever()
    await asyncio.sleep(3)
    await atv_remote.key_press("KEYCODE_DPAD_UP")
    await asyncio.sleep(10)
    atv_remote.disconnect()
    return 0

def update():
    global activiy
    if atv_remote is None:
        logging.debug("is none")
        return
    activiy = atv_remote.get_activity()
    logging.info(f"Changed activiy to: {activiy}")


if __name__ == '__main__':
    sys.exit(asyncio.run(main())) 