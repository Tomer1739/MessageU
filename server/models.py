import protocol


class Client:

    def __init__(self, client_id, name, public_key, last_seen):
        # convert string id to bytes if needed
        if isinstance(client_id, str):
            try:
                self.ID = bytes.fromhex(client_id)  # try as hex first
            except ValueError:
                self.ID = client_id.encode('utf-8')  # or as utf8
        else:
            self.ID = client_id

        # force name to be bytes
        self.Name = name if isinstance(name, bytes) else name.encode('utf-8')
        self.PublicKey = public_key
        self.LastSeen = last_seen

    def validate(self):
        """check client against protocol rules"""
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.Name or len(self.Name) >= protocol.NAME_SIZE:
            return False
        if not self.PublicKey or len(self.PublicKey) != protocol.PUBLIC_KEY_SIZE:
            return False
        if not self.LastSeen:
            return False
        return True

    def __str__(self):
        return f"Client(ID={self.ID.hex()}, Name={self.Name.decode('utf-8')})"


class Message:

    def __init__(self, to_client, from_client, msg_type, content):
        self.ID = 0  # db will set this later
        self.ToClient = to_client
        self.FromClient = from_client
        self.Type = msg_type
        self.Content = content

    def validate(self):
        """check message format"""
        if not self.ToClient or len(self.ToClient) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.FromClient or len(self.FromClient) != protocol.CLIENT_ID_SIZE:
            return False
        if not isinstance(self.Type, int) or self.Type < 1 or self.Type > protocol.MSG_TYPE_MAX:
            return False
        return True

    def __str__(self):
        return f"Message(ID={self.ID}, From={self.FromClient.hex()}, To={self.ToClient.hex()}, Type={self.Type})"