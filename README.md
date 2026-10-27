
Project by Tomer Gresler

This project was done as a final assignment in course 20937 defensive programming of the open university

To make it short, this project is a messaging app where the server was written in python and client in c++.

To run it you must have boost and crypto++(version used in the project is 8_8_0)

Enjoy messing with it and reding through.

The program starts from the main file.

Run the python main first to start the server, then the c++ main to run the client.


## Requirements

Server:
- Python 3.8 or newer (only the standard library is used)

Client:
- A C++17 compiler (Visual Studio 2019/2022 on Windows, g++ or clang on Linux)
- CMake 3.15 or newer
- Boost (only the header-only Asio part is used)
- Crypto++ (the code includes it as `<cryptopp880/...>`)
- A CPU with the RDRAND instruction (used to make the AES keys)

## Running the server

1. Put the port number in `server/myport.info` (for example `1357`). If the file is missing the server uses port 1357.
2. Start it:

```
cd server
python main.py
```

The server creates `defensive.db` in the folder it runs from, so clients and waiting messages are kept after a restart.

## Building the client

CMake finds the Crypto++ headers and copies them into `build/include/cryptopp880`, so the includes in the code work as they are.

Linux (Ubuntu / Debian):

```
sudo apt-get install libboost-dev libcrypto++-dev cmake g++
cmake -S client -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Windows (Visual Studio), with Crypto++ built from source in `C:\cryptopp880` and Boost in `C:\boost`:

```
cmake -S client -B build -A x64 -DBOOST_ROOT=C:/boost -DCRYPTOPP_HEADERS=C:/cryptopp880 -DCRYPTOPP_LIBRARY=C:/cryptopp880/x64/Output/Release/cryptlib.lib
cmake --build build --config Release
```

You can also open the `build` folder's `.sln` file in Visual Studio. If you got Boost and Crypto++ from vcpkg instead, pass `-DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static`.

## Running the client

Put the server address in a `server.info` file next to where you run the client, in the form `address:port`, for example:

```
127.0.0.1:1357
```

Then run `MessageUClient` (`build/MessageUClient` on Linux, `build\Release\MessageUClient.exe` on Windows).
After you register, the client saves your name, ID and private key in `me.info`, so you stay registered next time.
To run two clients on one machine, run each one from its own folder (each folder has its own `server.info` and `me.info`).

## Using the menu

Type the number of the option and press Enter.

- `110` Register: pick a username (letters and digits only).
- `120` Request for clients list: shows all other registered users. Do this first, the other options work with names from this list.
- `130` Request for public key: get a user's public key. You need it before sending them your symmetric key.
- `140` Request for waiting messages: shows the messages waiting for you on the server.
- `150` Send a text message: the message is encrypted with the symmetric key you share with that user.
- `151` Send a request for symmetric key: asks the other user to send you a symmetric key.
- `152` Send your symmetric key: makes a new symmetric key (if you don't have one with that user yet) and sends it, encrypted with their public key.
- `0` Exit.

Example for Alice sending a message to Bob:

1. Both register (`110`) and get the clients list (`120`).
2. Alice gets Bob's public key (`130`) and sends him a symmetric key (`152`).
3. Bob reads his waiting messages (`140`) and now has the key.
4. Alice sends a text message (`150`), Bob reads it with `140`.

Keys are only kept in memory, so they are lost when the client exits and the key exchange has to be done again.

## Running the tests

The tests start the real server on a free port in a temporary folder and talk to it over sockets. They only use Python's `unittest`:

```
cd server
python -m unittest discover -s tests -v
```

The tests and the client build (Linux and Windows) also run on GitHub Actions on every push.
