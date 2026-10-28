import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

# black box tests: start the real server and talk to it over sockets

SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CLIENT_ID_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
RESPONSE_HEADER_SIZE = 7
VERSION = 1

# request codes
REGISTRATION = 600
USERS = 601
PUBLIC_KEY = 602
SEND_MSG = 603
PENDING_MSG = 604

# response codes
RESPONSE_REGISTRATION = 2100
RESPONSE_USERS = 2101
RESPONSE_PUBLIC_KEY = 2102
RESPONSE_MSG_SENT = 2103
RESPONSE_PENDING_MSG = 2104
RESPONSE_ERROR = 9000

# message types
SEND_TEXT_MSG = 3


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def pack_request(client_id, code, payload=b''):
    return struct.pack(f"<{CLIENT_ID_SIZE}sBHL", client_id, VERSION, code, len(payload)) + payload


class ServerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # run the server in an empty folder so it gets a fresh database
        cls.work_dir = tempfile.TemporaryDirectory()
        cls.port = free_port()
        with open(os.path.join(cls.work_dir.name, 'myport.info'), 'w') as port_file:
            port_file.write(str(cls.port))

        cls.server = subprocess.Popen(
            [sys.executable, os.path.join(SERVER_DIR, 'main.py')],
            cwd=cls.work_dir.name,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # wait until the server listens
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', cls.port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            cls.server.kill()
            raise RuntimeError("server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.kill()
        cls.server.wait()
        cls.work_dir.cleanup()

    def setUp(self):
        self.assertIsNone(self.server.poll(), "server stopped running")

    # helpers

    def send_raw(self, data):
        """send one request and read everything until the server closes the connection"""
        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as sock:
            sock.sendall(data)
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def request(self, client_id, code, payload=b''):
        """send a request, check the response is exactly one header + payload, return (code, payload)"""
        response = self.send_raw(pack_request(client_id, code, payload))
        self.assertGreaterEqual(len(response), RESPONSE_HEADER_SIZE)
        version, response_code, payload_size = struct.unpack("<BHL", response[:RESPONSE_HEADER_SIZE])
        self.assertEqual(len(response), RESPONSE_HEADER_SIZE + payload_size, "response size does not match header")
        return response_code, response[RESPONSE_HEADER_SIZE:]

    def register(self, name, public_key=None):
        if public_key is None:
            public_key = os.urandom(PUBLIC_KEY_SIZE)
        payload = name.encode().ljust(NAME_SIZE, b'\0') + public_key
        return self.request(b'\0' * CLIENT_ID_SIZE, REGISTRATION, payload)

    def register_ok(self, name, public_key=None):
        code, payload = self.register(name, public_key)
        self.assertEqual(code, RESPONSE_REGISTRATION)
        self.assertEqual(len(payload), CLIENT_ID_SIZE)
        return payload

    def send_message(self, from_id, to_id, msg_type, content):
        payload = to_id + struct.pack("<BL", msg_type, len(content)) + content
        return self.request(from_id, SEND_MSG, payload)

    def pending(self, client_id):
        """returns list of (from_id, msg_id, type, content)"""
        code, payload = self.request(client_id, PENDING_MSG)
        self.assertEqual(code, RESPONSE_PENDING_MSG)
        messages = []
        offset = 0
        while offset < len(payload):
            from_id = payload[offset:offset + CLIENT_ID_SIZE]
            msg_id, msg_type, size = struct.unpack("<LBL", payload[offset + CLIENT_ID_SIZE:offset + CLIENT_ID_SIZE + 9])
            offset += CLIENT_ID_SIZE + 9
            messages.append((from_id, msg_id, msg_type, payload[offset:offset + size]))
            offset += size
        return messages

    # registration

    def test_registration(self):
        client_id = self.register_ok("regUser")
        self.assertNotEqual(client_id, b'\0' * CLIENT_ID_SIZE)

    def test_duplicate_name(self):
        self.register_ok("dupUser")
        code, payload = self.register("dupUser")
        self.assertEqual(code, RESPONSE_ERROR)
        self.assertEqual(payload, b'')

    def test_invalid_name(self):
        code, _ = self.register("bad name!")
        self.assertEqual(code, RESPONSE_ERROR)

    # clients list

    def test_clients_list(self):
        id_a = self.register_ok("listA")
        id_b = self.register_ok("listB")

        code, payload = self.request(id_a, USERS)
        self.assertEqual(code, RESPONSE_USERS)
        self.assertEqual(len(payload) % (CLIENT_ID_SIZE + NAME_SIZE), 0)

        users = {}
        for i in range(0, len(payload), CLIENT_ID_SIZE + NAME_SIZE):
            user_id = payload[i:i + CLIENT_ID_SIZE]
            name = payload[i + CLIENT_ID_SIZE:i + CLIENT_ID_SIZE + NAME_SIZE].rstrip(b'\0').decode()
            users[name] = user_id

        self.assertEqual(users.get("listB"), id_b)
        self.assertNotIn("listA", users)  # the asking client is not in its own list

    def test_clients_list_unknown_client(self):
        code, _ = self.request(os.urandom(CLIENT_ID_SIZE), USERS)
        self.assertEqual(code, RESPONSE_ERROR)

    # public key

    def test_public_key(self):
        key_b = os.urandom(PUBLIC_KEY_SIZE)
        id_a = self.register_ok("keyA")
        id_b = self.register_ok("keyB", key_b)

        code, payload = self.request(id_a, PUBLIC_KEY, id_b)
        self.assertEqual(code, RESPONSE_PUBLIC_KEY)
        self.assertEqual(payload, id_b + key_b)

    def test_public_key_unknown_target(self):
        id_a = self.register_ok("keyC")
        code, _ = self.request(id_a, PUBLIC_KEY, os.urandom(CLIENT_ID_SIZE))
        self.assertEqual(code, RESPONSE_ERROR)

    # send + pending messages

    def test_send_and_pending(self):
        id_a = self.register_ok("msgA")
        id_b = self.register_ok("msgB")
        content = b"encrypted text"

        code, payload = self.send_message(id_a, id_b, SEND_TEXT_MSG, content)
        self.assertEqual(code, RESPONSE_MSG_SENT)
        self.assertEqual(payload[:CLIENT_ID_SIZE], id_b)
        msg_id = struct.unpack("<L", payload[CLIENT_ID_SIZE:])[0]

        # request() also checks the response is sent only once
        messages = self.pending(id_b)
        self.assertEqual(messages, [(id_a, msg_id, SEND_TEXT_MSG, content)])

        # delivered messages are removed
        self.assertEqual(self.pending(id_b), [])

    def test_long_message(self):
        id_a = self.register_ok("longA")
        id_b = self.register_ok("longB")
        content = os.urandom(10000)  # bigger than one 1024 bytes packet

        code, _ = self.send_message(id_a, id_b, SEND_TEXT_MSG, content)
        self.assertEqual(code, RESPONSE_MSG_SENT)
        self.assertEqual(self.pending(id_b)[0][3], content)

    def test_no_pending_messages(self):
        id_a = self.register_ok("emptyA")
        self.assertEqual(self.pending(id_a), [])

    # bad requests

    def test_unknown_request_code(self):
        id_a = self.register_ok("codeA")
        code, _ = self.request(id_a, 999)
        self.assertEqual(code, RESPONSE_ERROR)

    def test_short_request(self):
        response = self.send_raw(b'\x01\x02\x03')
        self.assertEqual(struct.unpack("<BHL", response)[1], RESPONSE_ERROR)

    def test_send_to_unknown_client(self):
        id_a = self.register_ok("sendA")
        code, _ = self.send_message(id_a, os.urandom(CLIENT_ID_SIZE), SEND_TEXT_MSG, b"hi")
        self.assertEqual(code, RESPONSE_ERROR)

    def test_send_from_unknown_client(self):
        id_b = self.register_ok("sendB")
        code, _ = self.send_message(os.urandom(CLIENT_ID_SIZE), id_b, SEND_TEXT_MSG, b"hi")
        self.assertEqual(code, RESPONSE_ERROR)
        self.assertEqual(self.pending(id_b), [])

    def test_bad_message_type(self):
        id_a = self.register_ok("typeA")
        id_b = self.register_ok("typeB")
        code, _ = self.send_message(id_a, id_b, 7, b"hi")
        self.assertEqual(code, RESPONSE_ERROR)

    def test_content_size_too_big(self):
        id_a = self.register_ok("sizeA")
        id_b = self.register_ok("sizeB")
        # content size says 100 bytes but only 2 are sent
        payload = id_b + struct.pack("<BL", SEND_TEXT_MSG, 100) + b"hi"
        code, _ = self.request(id_a, SEND_MSG, payload)
        self.assertEqual(code, RESPONSE_ERROR)

    def test_client_reset_does_not_stop_server(self):
        # connect and reset the connection before sending anything
        sock = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.close()

        time.sleep(0.5)
        self.assertIsNone(self.server.poll(), "server stopped running")
        self.register_ok("afterReset")

    def test_many_requests_in_a_row(self):
        id_a = self.register_ok("manyA")
        for _ in range(10):
            code, _ = self.request(id_a, USERS)
            self.assertEqual(code, RESPONSE_USERS)


if __name__ == '__main__':
    unittest.main()
