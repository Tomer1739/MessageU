import sys
from server import Server


def parse_port(filepath):
    """try to get port from file"""
    try:
        with open(filepath, "r") as port_file:
            port = port_file.readline().strip()
            return int(port)
    except (ValueError, FileNotFoundError) as e:
        print(f"Error reading port: {e}")
        return None


def stop_server(error_message):
    print(f"\nFatal Error: {error_message}")
    print("MessageU Server will halt!")
    sys.exit(1)


def main():
    PORT_FILE = "myport.info"
    DEFAULT_PORT = 1357

    port = parse_port(PORT_FILE)
    if port is None:
        print("Trying again with myport.info.txt")
        PORT_FILE = "myport.info.txt"
        port = parse_port(PORT_FILE)
        if port is None:
            print(f"Failed to parse port from '{PORT_FILE}', using default port {DEFAULT_PORT}")
            port = DEFAULT_PORT

    server = Server('', port)
    if not server.start():
        stop_server(f"Server failed to start: {server.lastErr}")

    return 0


if __name__ == "__main__":
    sys.exit(main())