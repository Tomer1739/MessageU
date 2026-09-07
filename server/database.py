import sqlite3
from models import Client, Message


class Database:
    """handles client and message storage"""

    # table names
    CLIENTS = 'clients'
    MESSAGES = 'messages'

    def __init__(self, name='defensive.db'):
        self.name = name

    def connect(self):
        """opens db connection"""
        conn = sqlite3.connect(self.name)
        conn.text_factory = bytes  # store text as bytes for binary data
        return conn

    def executescript(self, script):
        """runs a sql script"""
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except Exception:
            # just ignore errors here
            pass
        finally:
            conn.close()

    def execute(self, query, args=(), commit=False, get_last_row=False):
        """runs a sql query"""
        results = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)

            if commit:
                conn.commit()
                results = True
            else:
                results = cur.fetchall()

            if get_last_row:
                results = cur.lastrowid
        except Exception as e:
            print(f"Database error: {e}")
            results = None
        finally:
            conn.close()

        return results

    def initialize(self):
        """creates tables if needed"""
        self.executescript(f"""
            CREATE TABLE IF NOT EXISTS {Database.CLIENTS}(
              ID BLOB(16) NOT NULL PRIMARY KEY,
              Name BLOB(255) NOT NULL,
              PublicKey BLOB(160) NOT NULL,
              LastSeen TEXT
            );
        """)

        self.executescript(f"""
            CREATE TABLE IF NOT EXISTS {Database.MESSAGES}(
              ID INTEGER PRIMARY KEY AUTOINCREMENT,
              ToClient BLOB(16) NOT NULL,
              FromClient BLOB(16) NOT NULL,
              Type INTEGER NOT NULL,
              Content BLOB,
              FOREIGN KEY(ToClient) REFERENCES {Database.CLIENTS}(ID),
              FOREIGN KEY(FromClient) REFERENCES {Database.CLIENTS}(ID)
            );
        """)

    def client_name_exists(self, username):
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE Name = ?", [username])
        return results and len(results) > 0

    def client_id_exists(self, client_id):
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        return results and len(results) > 0

    def store_client(self, client):
        if not isinstance(client, Client) or not client.validate():
            return False

        return self.execute(
            f"INSERT INTO {Database.CLIENTS} VALUES (?, ?, ?, ?)",
            [client.ID, client.Name, client.PublicKey, client.LastSeen],
            commit=True
        )

    def store_message(self, message):
        if not isinstance(message, Message) or not message.validate():
            return False

        # insert and get message id
        result = self.execute(
            f"INSERT INTO {Database.MESSAGES}(ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?)",
            [message.ToClient, message.FromClient, message.Type, message.Content],
            commit=True,
            get_last_row=True
        )

        return result

    def remove_message(self, msg_id):
        return self.execute(
            f"DELETE FROM {Database.MESSAGES} WHERE ID = ?",
            [msg_id],
            commit=True
        )

    def update_last_seen(self, client_id, timestamp):
        return self.execute(
            f"UPDATE {Database.CLIENTS} SET LastSeen = ? WHERE ID = ?",
            [timestamp, client_id],
            commit=True
        )

    def get_clients_list(self):
        return self.execute(
            f"SELECT ID, Name FROM {Database.CLIENTS}",
            []
        )

    def get_client_public_key(self, client_id):
        results = self.execute(
            f"SELECT PublicKey FROM {Database.CLIENTS} WHERE ID = ?",
            [client_id]
        )

        if not results or len(results) == 0:
            return None

        return results[0][0]  # first row, first column is the key

    def get_client_by_id(self, client_id):
        results = self.execute(
            f"SELECT ID, Name, PublicKey, LastSeen FROM {Database.CLIENTS} WHERE ID = ?",
            [client_id]
        )

        if not results or len(results) == 0:
            return None

        # make a client object
        row = results[0]
        return Client(row[0], row[1], row[2], row[3])

    def get_client_by_name(self, name):
        name_bytes = name if isinstance(name, bytes) else name.encode('utf-8')
        results = self.execute(
            f"SELECT ID, Name, PublicKey, LastSeen FROM {Database.CLIENTS} WHERE Name = ?",
            [name_bytes]
        )

        if not results or len(results) == 0:
            return None

        # make a client object
        row = results[0]
        return Client(row[0], row[1], row[2], row[3])

    def get_pending_messages(self, client_id):
        return self.execute(
            f"SELECT ID, FromClient, Type, Content FROM {Database.MESSAGES} WHERE ToClient = ?",
            [client_id]
        )