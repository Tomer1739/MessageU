import socket
import selectors
import uuid
import time
from datetime import datetime
import protocol
from database import Database
from models import Client
from message import MessageHandler


class Server:

    DATABASE_NAME = 'defensive.db'
    PACKET_SIZE = 1024
    MAX_QUEUED_CONN = 5
    IS_BLOCKING = False

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.database = Database(Server.DATABASE_NAME)
        self.message_handler = MessageHandler(self.database)
        self.lastErr = ""

        # mapping request codes to handlers
        self.request_handlers = {
            protocol.ERequestCode.REQUEST_REGISTRATION.value: self.handle_registration,
            protocol.ERequestCode.REQUEST_USERS.value: self.handle_users_list,
            protocol.ERequestCode.REQUEST_PUBLIC_KEY.value: self.handle_public_key,
            protocol.ERequestCode.REQUEST_SEND_MSG.value: self.handle_message_send,
            protocol.ERequestCode.REQUEST_PENDING_MSG.value: self.handle_pending_messages
        }

    def accept(self, sock, mask):
        """accept new connections"""
        conn, addr = sock.accept()
        conn.setblocking(Server.IS_BLOCKING)
        self.sel.register(conn, selectors.EVENT_READ, self.read)
        print(f"New connection from {addr}")

    def read(self, conn, mask):
        """read data from client"""
        print("Client connected, reading data...")
        data = conn.recv(Server.PACKET_SIZE)

        if data:
            request_header = protocol.RequestHeader()
            success = False

            if not request_header.unpack(data):
                print("Failed to parse request header")
            else:
                if request_header.code in self.request_handlers:
                    response_data = self.request_handlers[request_header.code](conn, data)
                    success = response_data and self.write(conn, response_data)
                else:
                    print(f"Unknown request code: {request_header.code}")

            # send error if handling failed
            if not success:
                error_response = protocol.ErrorResponse()
                self.write(conn, error_response.pack())

            # update client's last seen time
            if request_header.clientID:
                try:
                    self.database.update_last_seen(request_header.clientID, str(datetime.now()))
                except Exception as e:
                    print(f"Failed to update last seen: {e}")

        time.sleep(1)
        self.sel.unregister(conn)
        conn.close()

    def write(self, conn, data):
        """send data back to client"""
        if not data:
            return False

        size = len(data)
        sent = 0

        while sent < size:
            # how much to send in this chunk
            chunk_size = min(Server.PACKET_SIZE, size - sent)
            chunk = data[sent:sent + chunk_size]

            try:
                # send chunk
                bytes_sent = conn.send(chunk)
                if bytes_sent == 0:
                    print("Socket connection broken")
                    return False
                sent += bytes_sent
            except Exception as e:
                print(f"Failed to send response: {e}")
                return False

        print(f"Response sent successfully ({size} bytes)")
        return True

    def start(self):
        """start server and listen for connections"""
        self.database.initialize()

        try:
            # create socket and bind
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen(Server.MAX_QUEUED_CONN)
            sock.setblocking(Server.IS_BLOCKING)

            self.sel.register(sock, selectors.EVENT_READ, self.accept)
        except Exception as e:
            self.lastErr = str(e)
            return False

        print(f"Server is listening for connections on port {self.port}...")

        try:
            # starting everything
            while True:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
        except KeyboardInterrupt:
            print("Server shutting down...")
        except Exception as e:
            print(f"Server error: {e}")
            return False
        finally:
            self.sel.close()

        return True

    def handle_registration(self, conn, data):
        """handle client registration"""
        request = protocol.RegistrationRequest()
        response = protocol.RegistrationResponse()

        # parse request
        if not request.unpack(data):
            print("Failed to parse registration request")
            return None

        try:
            # username needs to be alphanumeric
            if not request.name.isalnum():
                print(f"Invalid username: {request.name}")
                return None

            # can't reuse existing username
            if self.database.client_name_exists(request.name.encode('utf-8')):
                print(f"Username already exists: {request.name}")
                return None
        except Exception as e:
            print(f"Registration request error: {e}")
            return None

        # create a new UUID for client
        client_id = uuid.uuid4().hex
        client_id_bytes = bytes.fromhex(client_id)

        # new client object
        client = Client(
            client_id_bytes,
            request.name.encode('utf-8'),
            request.publicKey,
            str(datetime.now())
        )

        if not self.database.store_client(client):
            print(f"Failed to store client: {request.name}")
            return None

        print(f"Successfully registered client: {request.name}")

        # prepare response
        response.clientID = client_id_bytes
        response.header.payloadSize = protocol.CLIENT_ID_SIZE

        return response.pack()

    def handle_users_list(self, conn, data):
        """handle request for users list"""
        request_header = protocol.RequestHeader()

        # parse header
        if not request_header.unpack(data):
            print("Failed to parse users list request header")
            return None

        try:
            # check client exists
            if not self.database.client_id_exists(request_header.clientID):
                print(f"Client ID does not exist: {request_header.clientID.hex()}")
                return None

            # get all clients
            clients = self.database.get_clients_list()

            # create response (exclude requesting client)
            response = protocol.UsersListResponse()
            response.users = [(client_id, name) for client_id, name in clients
                              if client_id != request_header.clientID]

            print(f"Sending list of {len(response.users)} clients")
            return response.pack()

        except Exception as e:
            print(f"Users list request error: {e}")
            return None

    def handle_public_key(self, conn, data):
        """handle request for public key"""
        request = protocol.PublicKeyRequest()

        # parse request
        if not request.unpack(data):
            print("Failed to parse public key request")
            return None

        # get public key from db
        public_key = self.database.get_client_public_key(request.clientID)
        if not public_key:
            print(f"Client ID not found: {request.clientID.hex()}")
            return None

        # make response
        response = protocol.PublicKeyResponse()
        response.clientID = request.clientID
        response.publicKey = public_key
        response.header.payloadSize = protocol.CLIENT_ID_SIZE + protocol.PUBLIC_KEY_SIZE

        print(f"Sending public key for client: {request.clientID.hex()}")
        return response.pack()

    def handle_message_send(self, conn, data):
        """handle message sending between clients"""
        return self.message_handler.handle_message_send(conn, data)

    def handle_pending_messages(self, conn, data):
        """handle requests for pending messages"""
        request_header = protocol.RequestHeader()

        # parse request
        if not request_header.unpack(data):
            print("Failed to parse pending messages request header")
            return None

        try:
            # check client exists
            if not self.database.client_id_exists(request_header.clientID):
                print(f"Client ID does not exist: {request_header.clientID.hex()}")
                return None

            # get messages waiting for this client
            response_data, message_ids = self.message_handler.handle_pending_messages(request_header.clientID)

            if response_data:
                success = self.write(conn, response_data)

                # remove messages that were delivered
                if success and message_ids:
                    self.message_handler.remove_delivered_messages(message_ids)

                return response_data

            return None
        except Exception as e:
            print(f"Error processing pending messages request: {e}")
            return None