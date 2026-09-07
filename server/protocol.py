import struct
from enum import Enum

# protocol constants
SERVER_VERSION = 2
CLIENT_ID_SIZE = 16  # 16 bytes for client id
NAME_SIZE = 255  # max client name length
PUBLIC_KEY_SIZE = 160  # public key size in bytes
HEADER_SIZE = 7  # header size
MSG_ID_SIZE = 4  # msg id size
MSG_TYPE_MAX = 3  # highest message type

# request codes
class ERequestCode(Enum):
    REQUEST_REGISTRATION = 600  # client registration
    REQUEST_USERS = 601  # client list request
    REQUEST_PUBLIC_KEY = 602  # public key request
    REQUEST_SEND_MSG = 603  # send message
    REQUEST_PENDING_MSG = 604  # pending messages

# response codes
class EResponseCode(Enum):
    RESPONSE_REGISTRATION = 2100  # registration successful
    RESPONSE_USERS = 2101  # client list
    RESPONSE_PUBLIC_KEY = 2102  # public key
    RESPONSE_MSG_SENT = 2103  # message received by server
    RESPONSE_PENDING_MSG = 2104  # pending messages
    RESPONSE_ERROR = 9000  # error

# message types
class EMessageType(Enum):
    REQUEST_SYM_KEY = 1  # requesting symmetric key
    SEND_SYM_KEY = 2  # sending symmetric key
    SEND_TEXT_MSG = 3  # sending text message

class RequestHeader:
    """client request header"""

    def __init__(self):
        self.clientID = b""  # 16 bytes
        self.version = 0
        self.code = 0
        self.payloadSize = 0
        self.SIZE = CLIENT_ID_SIZE + HEADER_SIZE

    def unpack(self, data):
        """unpack binary data into header fields"""
        try:
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])[0]
            headerData = data[CLIENT_ID_SIZE:CLIENT_ID_SIZE + HEADER_SIZE]
            self.version, self.code, self.payloadSize = struct.unpack("<BHL", headerData)
            return True
        except Exception:
            self.__init__()  # reset on failure
            return False


class ResponseHeader:
    """server response header"""

    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payloadSize = 0
        self.SIZE = HEADER_SIZE

    def pack(self):
        """pack header to binary format"""
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except Exception:
            return b""


class RegistrationRequest:

    def __init__(self):
        self.header = RequestHeader()
        self.name = ""
        self.publicKey = b""

    def unpack(self, data):
        """parse registration request"""
        if not self.header.unpack(data):
            return False
        try:
            # get name (null terminated)
            nameData = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))

            # get public key
            keyData = data[self.header.SIZE + NAME_SIZE:self.header.SIZE + NAME_SIZE + PUBLIC_KEY_SIZE]
            self.publicKey = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", keyData)[0]
            return True
        except Exception:
            self.name = ""
            self.publicKey = b""
            return False


class RegistrationResponse:

    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_REGISTRATION.value)
        self.clientID = b""

    def pack(self):
        """create response packet"""
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except Exception:
            return b""


class UsersListResponse:

    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_USERS.value)
        self.users = []  # list of (clientID, name) tuples

    def pack(self):
        """create users list response"""
        try:
            data = self.header.pack()
            payload = b""

            # pack each user
            for clientID, name in self.users:
                payload += clientID

                if isinstance(name, bytes):
                    name_bytes = name + b'\0' * (NAME_SIZE - len(name))
                else:
                    name_bytes = name.encode('utf-8') + b'\0' * (NAME_SIZE - len(name.encode('utf-8')))

                payload += name_bytes[:NAME_SIZE]

            self.header.payloadSize = len(payload)
            data = self.header.pack() + payload
            return data
        except Exception as e:
            print(f"Error packing users list response: {e}")
            return b""


class PublicKeyRequest:

    def __init__(self):
        self.header = RequestHeader()
        self.clientID = b""

    def unpack(self, data):
        """parse public key request"""
        if not self.header.unpack(data):
            return False
        try:
            clientID = data[self.header.SIZE:self.header.SIZE + CLIENT_ID_SIZE]
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", clientID)[0]
            return True
        except Exception:
            self.clientID = b""
            return False


class PublicKeyResponse:

    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_PUBLIC_KEY.value)
        self.clientID = b""
        self.publicKey = b""

    def pack(self):
        """create public key response"""
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<{PUBLIC_KEY_SIZE}s", self.publicKey)
            self.header.payloadSize = CLIENT_ID_SIZE + PUBLIC_KEY_SIZE
            data = self.header.pack() + data[self.header.SIZE:]
            return data
        except Exception:
            return b""


class MessageSendRequest:

    def __init__(self):
        self.header = RequestHeader()
        self.toClientID = b""
        self.messageType = 0
        self.contentSize = 0
        self.content = b""

    def unpack(self, conn, data):
        """parse message send request"""
        if not self.header.unpack(data):
            return False
        try:
            # get recipient id
            targetID = data[self.header.SIZE:self.header.SIZE + CLIENT_ID_SIZE]
            self.toClientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", targetID)[0]

            # get message type and content size
            offset = self.header.SIZE + CLIENT_ID_SIZE
            self.messageType, self.contentSize = struct.unpack("<BL", data[offset:offset + 5])

            # get content
            offset = self.header.SIZE + CLIENT_ID_SIZE + 5
            bytesRead = len(data) - offset
            if bytesRead > self.contentSize:
                bytesRead = self.contentSize

            self.content = data[offset:offset + bytesRead]

            # read more if needed
            while bytesRead < self.contentSize:
                chunk = conn.recv(1024)
                chunkSize = min(len(chunk), self.contentSize - bytesRead)
                self.content += chunk[:chunkSize]
                bytesRead += chunkSize

            return True
        except Exception:
            self.toClientID = b""
            self.messageType = 0
            self.contentSize = 0
            self.content = b""
            return False


class MessageSentResponse:

    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_MSG_SENT.value)
        self.clientID = b""
        self.messageID = 0

    def pack(self):
        """create message sent response"""
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}sL", self.clientID, self.messageID)
            self.header.payloadSize = CLIENT_ID_SIZE + MSG_ID_SIZE
            data = self.header.pack() + data[self.header.SIZE:]
            return data
        except Exception:
            return b""


class PendingMessage:

    def __init__(self):
        self.fromClientID = b""
        self.messageID = 0
        self.messageType = 0
        self.contentSize = 0
        self.content = b""

    def pack(self):
        """create pending message packet"""
        try:
            data = struct.pack(f"<{CLIENT_ID_SIZE}s", self.fromClientID)
            data += struct.pack("<LBL", self.messageID, self.messageType, self.contentSize)
            data += self.content
            return data
        except Exception:
            return b""


class PendingMessagesResponse:

    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_PENDING_MSG.value)
        self.messages = []

    def pack(self):
        """create pending messages response"""
        try:
            data = self.header.pack()
            payload = b""

            # add each message
            for msg in self.messages:
                payload += msg.pack()

            self.header.payloadSize = len(payload)
            data = self.header.pack() + payload
            return data
        except Exception:
            return b""


class ErrorResponse:

    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_ERROR.value)

    def pack(self):
        """create error response"""
        try:
            return self.header.pack()
        except Exception:
            return b""