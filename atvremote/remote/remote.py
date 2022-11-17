import ssl
import sys
import select
import socket
import logging
import remote.messages as messages

logger = logging.getLogger(__name__)

class Remote:
    def __init__(self, hostname: str, port: int = 6466) -> None:
        self.hostname = hostname
        self.port = port

    def connect_to_androidtv(self, ssock: ssl.SSLSocket):
        #Receive configure message:
        messages.CommandMessage.receive_response(ssock)
        messages.ConfigurationMessage().send(ssock)
        messages.CommandMessage.receive_response(ssock)
        messages.SetActiveMessage().send(ssock)
        messages.CommandMessage.receive_response(ssock)
        msg = messages.CommandMessage()
        msg.message.remote_ime_show_request.remote_text_field_status.counter_field = 0
        #msg.send(ssock)
        #messages.CommandMessage.receive_response(ssock)


    def loop(self) -> bool:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations('cert/pub_cert.pem')
        
        context.load_cert_chain('cert/priv_cert.pem','cert/key.pem', password=b"password")
        context.check_hostname = False
        context.verify_mode = context.verify_mode.CERT_OPTIONAL
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with context.wrap_socket(sock, server_hostname=self.hostname, do_handshake_on_connect=False) as ssock:
                ssock.connect((self.hostname, self.port))
                ssock.do_handshake(block=True)
                ssock.setblocking(True)
                self.connect_to_androidtv(ssock)
                #ssock.setblocking(False)
                while True:
                    # Wait for input from stdin & socket
                    inputready, outputready,exceptrdy = select.select([sys.stdin, ssock], [],[])
                    for input in inputready:
                        if input == sys.stdin:
                            pass
                        elif input == ssock:
                            #logger.debug("Receive a message")
                            msg = messages.CommandMessage.receive_response(ssock)
                            if msg.HasField('remote_ping_request'):
                                #ssock.setblocking(True)
                                messages.PingResponseMessage(msg.remote_ping_request.val1).send(ssock)
                                #ssock.setblocking(False)
                        
                        