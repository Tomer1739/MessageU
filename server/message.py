import protocol
from models import Message


class MessageHandler:
    """handles message processing between clients"""

    def __init__(self, database):
        self.db = database

    def handle_message_send(self, conn, request_data):
        request = protocol.MessageSendRequest()
        response = protocol.MessageSentResponse()

        # try to parse request
        if not request.unpack(conn, request_data):
            print("Failed to parse message send request")
            return False

        # check target exists
        if not self.db.client_id_exists(request.toClientID):
            print(f"Target client ID ({request.toClientID.hex()}) does not exist")
            return False

        # make a message object
        message = Message(
            request.toClientID,
            request.header.clientID,
            request.messageType,
            request.content
        )

        msg_id = self.db.store_message(message)
        if not msg_id:
            print("Failed to store message")
            return False

        # prepare response
        response.header.payloadSize = protocol.CLIENT_ID_SIZE + protocol.MSG_ID_SIZE
        response.clientID = request.toClientID
        response.messageID = msg_id

        print(f"Message from client ID ({request.header.clientID.hex()}) "
              f"to client ID ({request.toClientID.hex()}) successfully stored "
              f"with ID {msg_id}")

        return response.pack()

    def _validate_message_type_content(self, request):
        if request.messageType == protocol.EMessageType.REQUEST_SYM_KEY.value:
            if request.contentSize != 0 or request.content:
                print("Warning: Symmetric key request should have empty content")
                request.contentSize = 0
                request.content = b''

        elif request.messageType == protocol.EMessageType.SEND_SYM_KEY.value:
            if not request.content:
                print("Warning: Symmetric key message has empty content")

        elif request.messageType == protocol.EMessageType.SEND_TEXT_MSG.value:
            if not request.content:
                print("Warning: Text message has empty content")

    def handle_pending_messages(self, client_id):
        response = protocol.PendingMessagesResponse()

        # check client exists
        if not self.db.client_id_exists(client_id):
            print(f"Client ID ({client_id.hex()}) does not exist")
            return False, []

        # get messages for this client
        messages = self.db.get_pending_messages(client_id)
        message_ids = []

        # process each message
        for msg_data in messages:
            msg_id, from_client, msg_type, content = msg_data

            pending_msg = protocol.PendingMessage()
            pending_msg.messageID = msg_id
            pending_msg.fromClientID = from_client
            pending_msg.messageType = msg_type
            pending_msg.contentSize = len(content) if content else 0
            pending_msg.content = content or b''

            message_ids.append(msg_id)
            response.messages.append(pending_msg)

        # calc response size
        payload_size = sum(len(msg.pack()) for msg in response.messages)
        response.header.payloadSize = payload_size

        print(f"Found {len(message_ids)} pending messages for client ID ({client_id.hex()})")

        return response.pack(), message_ids

    def remove_delivered_messages(self, message_ids):
        for msg_id in message_ids:
            self.db.remove_message(msg_id)

        print(f"Removed {len(message_ids)} delivered messages")