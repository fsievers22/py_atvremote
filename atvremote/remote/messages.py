import remote.proto.commands_pb2 as commands
import logging
import ssl


logger = logging.getLogger(__name__)

class CommandMessage:
    def __init__(self) -> None:
        self.message = commands.RemoteMessage()

    def serialize(self) -> bytes:
        serialized_message = self.message.SerializeToString()
        len_bytes = len(serialized_message).to_bytes(1,'little')
        #logger.debug(f"[{len_bytes}], {serialized_message}")
        return len_bytes + serialized_message

    def send(self, socket: ssl.SSLSocket):
        socket.send(self.serialize())

    def receive_response(socket: ssl.SSLSocket) -> commands.RemoteMessage:
        data = socket.recv(2048)
        message_len = data[0]
        #logger.debug(f"Receiving message with length {message_len}")
        data = data[1:len(data)]
        while len(data) != message_len:
            data += socket.recv(2048)
        pairing_message = commands.RemoteMessage()
        pairing_message.ParseFromString(data)
        if(not(pairing_message.HasField('remote_ping_request'))):
            logger.debug("Received message from android tv:")
            logger.debug(pairing_message)
        return pairing_message

class ConfigurationMessage(CommandMessage):
    def __init__(self) -> None:
        super().__init__()
        self.message.remote_configure.code1 = 639
        self.message.remote_configure.device_info.model = "model"
        self.message.remote_configure.device_info.vendor = "vendor"
        self.message.remote_configure.device_info.app_version = "1.0.0"
        self.message.remote_configure.device_info.package_name = "vendor.model"
        self.message.remote_configure.device_info.unknown1 = 2
        self.message.remote_configure.device_info.unknown2 = "11"

class SetActiveMessage(CommandMessage):
    def __init__(self) -> None:
        super().__init__()
        self.message.remote_set_active.active = 639

class PingResponseMessage(CommandMessage):
    def __init__(self, val1) -> None:
        super().__init__()
        self.message.remote_ping_response.val1 = val1
        