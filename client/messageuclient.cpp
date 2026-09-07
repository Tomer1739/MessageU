#include "messageuclient.h"
#include "protocol.h"
#include "Base64Wrapper.h"
#include "AESWrapper.h"
#include <iostream>
#include <fstream>
#include <sstream>

MessageUClient::MessageUClient()
    : m_serverPort(0), m_isRegistered(false), m_isRunning(false), m_rsaPrivate(nullptr) {
}

MessageUClient::~MessageUClient() = default;

bool MessageUClient::initialize() {
    if (!loadServerInfo()) {
        displayError("Failed to load server information.");
        return false;
    }

    m_isRegistered = loadClientInfo();

    return true;
}

void MessageUClient::run() {
    m_isRunning = true;

    while (m_isRunning) {
        displayMenu();

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "110") {
            if (m_isRegistered) {
                displayError("You are already registered.");
            }
            else {
                registerClient();
            }
        }
        else if (choice == "120") {
            if (!m_isRegistered) {
                displayError("You must register first.");
            }
            else {
                requestClientsList();
            }
        }
        else if (choice == "130") {
            if (!m_isRegistered) {
                displayError("You must register first.");
            }
            else {
                std::cout << "Enter username: ";
                std::string username;
                std::getline(std::cin, username);
                requestPublicKey(username);
            }
        }
        else if (choice == "140") {
            if (!m_isRegistered) {
                displayError("You must register first.");
            }
            else {
                requestPendingMessages();
            }
        }
        else if (choice == "150") {
            if (!m_isRegistered) {
                displayError("You must register first.");
            }
            else {
                std::cout << "Enter username: ";
                std::string username;
                std::getline(std::cin, username);

                std::cout << "Enter message text: ";
                std::string messageText;
                std::getline(std::cin, messageText);

                sendTextMessage(username, messageText);
            }
        }
        else if (choice == "151") {
            if (!m_isRegistered) {
                displayError("You must register first.");
            }
            else {
                std::cout << "Enter username: ";
                std::string username;
                std::getline(std::cin, username);

                sendSymKeyRequest(username);
            }
        }
        else if (choice == "152") {
            if (!m_isRegistered) {
                displayError("You must register first.");
            }
            else {
                std::cout << "Enter username: ";
                std::string username;
                std::getline(std::cin, username);

                sendSymKey(username);
            }
        }
        else if (choice == "0") {
            m_isRunning = false;
        }
        else {
            displayError("Invalid choice. Please try again.");
        }
    }
}

bool MessageUClient::loadServerInfo() {
    try {
        std::ifstream file("server.info");
        if (!file.is_open()) {
            file = std::ifstream("server.info.txt");
            if (!file.is_open()) {
                return false;
            }
        }

        std::string serverInfo;
        std::getline(file, serverInfo);

        // parse the server info (format: address:port)
        size_t colonPos = serverInfo.find(':');
        if (colonPos == std::string::npos) {
            return false;
        }

        m_serverAddress = serverInfo.substr(0, colonPos);
        m_serverPort = std::stoi(serverInfo.substr(colonPos + 1));

        return true;
    }
    catch (const std::exception& e) {
        displayError(std::string("Error loading server info: ") + e.what());
        return false;
    }
}

bool MessageUClient::saveClientInfo(const std::string& name, const std::vector<uint8_t>& clientId, const std::string& privateKey) {
    try {
        std::ofstream file("me.info");
        if (!file.is_open()) {
            return false;
        }

        file << name << std::endl;

        file << Protocol::bytesToHex(clientId) << std::endl;

        std::string base64PrivateKey = Base64Wrapper::encode(privateKey);

        file << base64PrivateKey;

        return true;
    }
    catch (const std::exception& e) {
        displayError(std::string("Error saving client info: ") + e.what());
        return false;
    }
}

bool MessageUClient::loadClientInfo() {
    try {
        std::ifstream file("me.info");
        if (!file.is_open()) {
            return false;
        }

        std::getline(file, m_clientName);

        // read client id (second line) as hex string
        std::string clientIdHex;
        std::getline(file, clientIdHex);
        m_clientId = Protocol::hexToBytes(clientIdHex);

        // read private key (base64 encoded)
        std::string base64PrivateKey;
        std::string line;
        while (std::getline(file, line)) {
            base64PrivateKey += line;
        }

        std::string privateKeyStr = Base64Wrapper::decode(base64PrivateKey);

        try {
            m_rsaPrivate = std::make_unique<RSAPrivateWrapper>(privateKeyStr);
            return true;
        }
        catch (const std::exception& e) {
            displayError(std::string("Error initializing private key: ") + e.what());
            return false;
        }
    }
    catch (const std::exception& e) {
        displayError(std::string("Error loading client info: ") + e.what());
        return false;
    }
}

bool MessageUClient::connectToServer() {
    if (m_networkManager.isConnected()) {
        return true;
    }

    return m_networkManager.connect(m_serverAddress, m_serverPort);
}

bool MessageUClient::registerClient() {
    std::cout << "Enter username: ";
    std::string username;
    std::getline(std::cin, username);

    if (username.length() >= Protocol::NAME_SIZE) {
        displayError("Username too long. Maximum length is " + std::to_string(Protocol::NAME_SIZE - 1));
        return false;
    }

    // check username is alphanumeric
    for (char c : username) {
        if (!std::isalnum(c)) {
            displayError("Username must be alphanumeric.");
            return false;
        }
    }

    m_rsaPrivate = std::make_unique<RSAPrivateWrapper>();

    // get public key as string and convert to vector for protocol
    std::string publicKeyStr = m_rsaPrivate->getPublicKey();
    std::vector<uint8_t> publicKey(publicKeyStr.begin(), publicKeyStr.end());

    if (!connectToServer()) {
        displayError("Failed to connect to server.");
        return false;
    }

    std::vector<uint8_t> request = Protocol::packRegistrationRequest(username, publicKey);

    if (!m_networkManager.send(request)) {
        displayError("Failed to send registration request.");
        return false;
    }

    std::vector<uint8_t> response = m_networkManager.receive();

    // parse response
    std::vector<uint8_t> clientId;
    if (!Protocol::parseRegistrationResponse(response, clientId)) {
        displayError("Invalid registration response from server.");
        return false;
    }

    // save client info
    m_clientName = username;
    m_clientId = clientId;
    m_isRegistered = true;

    if (!saveClientInfo(username, clientId, m_rsaPrivate->getPrivateKey())) {
        displayError("Failed to save client information.");
        return false;
    }

    std::cout << "Registration successful. Your client ID: " << Protocol::bytesToHex(clientId) << std::endl;
    return true;
}

bool MessageUClient::requestClientsList() {
    if (!connectToServer()) {
        displayError("Failed to connect to server.");
        return false;
    }

    std::vector<uint8_t> request = Protocol::packRequestHeader(m_clientId, 1, Protocol::ERequestCode::REQUEST_USERS, 0);

    if (!m_networkManager.send(request)) {
        displayError("Failed to send client list request.");
        return false;
    }

    std::vector<uint8_t> response = m_networkManager.receive();

    // parse response
    if (response.size() < sizeof(Protocol::ResponseHeader)) {
        displayError("Invalid response from server.");
        return false;
    }

    Protocol::ResponseHeader header;
    std::memcpy(&header, response.data(), sizeof(Protocol::ResponseHeader));

    if (header.code != static_cast<uint16_t>(Protocol::EResponseCode::RESPONSE_USERS)) {
        displayError("Server responded with an error.");
        return false;
    }

    m_clients.clear();

    size_t offset = sizeof(Protocol::ResponseHeader);
    size_t entrySize = Protocol::CLIENT_ID_SIZE + Protocol::NAME_SIZE;
    size_t count = header.payloadSize / entrySize;

    for (size_t i = 0; i < count; i++) {
        // get client id
        std::vector<uint8_t> clientId(Protocol::CLIENT_ID_SIZE);
        std::copy(response.begin() + offset, response.begin() + offset + Protocol::CLIENT_ID_SIZE, clientId.begin());
        offset += Protocol::CLIENT_ID_SIZE;

        // get client name
        std::string name;
        for (size_t j = 0; j < Protocol::NAME_SIZE; j++) {
            char c = static_cast<char>(response[offset + j]);
            if (c == '\0') break;
            name += c;
        }
        offset += Protocol::NAME_SIZE;

        // add client to list
        m_clients[name] = Client(clientId, name);
    }

    displayClientsList();

    return true;
}

bool MessageUClient::requestPublicKey(const std::string& clientName) {
    Client* client = findClientByName(clientName);
    if (!client) {
        displayError("Client not found. Try getting the client list first.");
        return false;
    }

    if (!connectToServer()) {
        displayError("Failed to connect to server.");
        return false;
    }

    std::vector<uint8_t> request = Protocol::packPublicKeyRequest(client->getID());

    // update client id in header
    std::copy(m_clientId.begin(), m_clientId.end(), request.begin());

    if (!m_networkManager.send(request)) {
        displayError("Failed to send public key request.");
        return false;
    }

    std::vector<uint8_t> response = m_networkManager.receive();

    // parse response
    if (response.size() < sizeof(Protocol::ResponseHeader)) {
        displayError("Invalid response from server.");
        return false;
    }

    Protocol::ResponseHeader header;
    std::memcpy(&header, response.data(), sizeof(Protocol::ResponseHeader));

    if (header.code != static_cast<uint16_t>(Protocol::EResponseCode::RESPONSE_PUBLIC_KEY)) {
        displayError("Server responded with an error.");
        return false;
    }

    // get client id and public key
    if (header.payloadSize != Protocol::CLIENT_ID_SIZE + Protocol::PUBLIC_KEY_SIZE) {
        displayError("Invalid public key response size.");
        return false;
    }

    size_t offset = sizeof(Protocol::ResponseHeader);

    // get client id
    std::vector<uint8_t> clientId(Protocol::CLIENT_ID_SIZE);
    std::copy(response.begin() + offset, response.begin() + offset + Protocol::CLIENT_ID_SIZE, clientId.begin());
    offset += Protocol::CLIENT_ID_SIZE;

    // get public key
    std::vector<uint8_t> publicKey(Protocol::PUBLIC_KEY_SIZE);
    std::copy(response.begin() + offset, response.begin() + offset + Protocol::PUBLIC_KEY_SIZE, publicKey.begin());

    client->setPublicKey(publicKey);

    std::cout << "Received public key for client: " << clientName << std::endl;
    return true;
}

bool MessageUClient::requestPendingMessages() {
    if (!connectToServer()) {
        displayError("Failed to connect to server.");
        return false;
    }

    std::vector<uint8_t> request = Protocol::packRequestHeader(m_clientId, 1, Protocol::ERequestCode::REQUEST_PENDING_MSG, 0);

    if (!m_networkManager.send(request)) {
        displayError("Failed to send pending messages request.");
        return false;
    }

    std::vector<uint8_t> response = m_networkManager.receive();

    // parse response
    if (response.size() < sizeof(Protocol::ResponseHeader)) {
        displayError("Invalid response from server.");
        return false;
    }

    Protocol::ResponseHeader header;
    std::memcpy(&header, response.data(), sizeof(Protocol::ResponseHeader));

    if (header.code != static_cast<uint16_t>(Protocol::EResponseCode::RESPONSE_PENDING_MSG)) {
        displayError("Server responded with an error.");
        return false;
    }

    try {
        // parse pending messages
        size_t offset = sizeof(Protocol::ResponseHeader);
        size_t msgHeaderSize = Protocol::CLIENT_ID_SIZE + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t);

        // get data
        while (offset + msgHeaderSize <= response.size()) {
            std::vector<uint8_t> fromClientId(Protocol::CLIENT_ID_SIZE);
            std::copy(response.begin() + offset, response.begin() + offset + Protocol::CLIENT_ID_SIZE, fromClientId.begin());
            offset += Protocol::CLIENT_ID_SIZE;

            uint32_t messageId = 0;
            std::memcpy(&messageId, response.data() + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);

            uint8_t messageType = response[offset];
            offset += sizeof(uint8_t);

            uint32_t contentSize = 0;
            std::memcpy(&contentSize, response.data() + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);

            // check content size before extracting
            std::vector<uint8_t> content;
            if (contentSize > 0) {
                if (offset + contentSize > response.size()) {
                    displayError("Invalid message content size. Message truncated.");
                    break;
                }

                content.resize(contentSize);
                std::copy(response.begin() + offset, response.begin() + offset + contentSize, content.begin());
                offset += contentSize;
            }

            // create and process message
            try {
                Message message(m_clientId, fromClientId,
                    static_cast<Protocol::EMessageType>(messageType),
                    content);
                message.setID(messageId);

                if (message.getType() == Protocol::EMessageType::SEND_SYM_KEY && m_rsaPrivate) {
                    try {
                        std::string encryptedKeyStr(message.getContent().begin(), message.getContent().end());

                        std::string symKeyStr = m_rsaPrivate->decrypt(encryptedKeyStr);

                        std::vector<uint8_t> symKey(symKeyStr.begin(), symKeyStr.end());

                        for (auto& pair : m_clients) {
                            if (pair.second.getID() == message.getFromClient()) {
                                pair.second.setSymmetricKey(symKey);
                                break;
                            }
                        }
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Error processing symmetric key: " << e.what() << std::endl;
                    }
                }

                displayMessage(message);
            }
            catch (const std::exception& e) {
                std::cerr << "Error processing message: " << e.what() << std::endl;
                // continue to next message
            }
        }
    }
    catch (const std::exception& e) {
        displayError(std::string("Error processing messages: ") + e.what());
        return false;
    }

    return true;
}

bool MessageUClient::sendTextMessage(const std::string& clientName, const std::string& messageText) {
    if (messageText.length() > 32) {
        displayError("Message too long. Maximum length is 32");
        return false;
    }

    Client* client = findClientByName(clientName);
    if (!client) {
        displayError("Client not found, try getting the client list first.");
        return false;
    }

    if (!client->hasSymmetricKey()) {
        displayError("No symmetric key available for this client. Request or send a symmetric key first");
        return false;
    }

    AESWrapper aes(client->getSymmetricKey().data(), client->getSymmetricKey().size());

    std::string encryptedMessage = aes.encrypt(messageText.c_str(), messageText.length());

    // convert to vector<uint8_t> for the protocol
    std::vector<uint8_t> encryptedMessageVec(encryptedMessage.begin(), encryptedMessage.end());

    if (!connectToServer()) {
        displayError("Failed to connect to server.");
        return false;
    }

    std::vector<uint8_t> request = Protocol::packSendMessageRequest(
        client->getID(),
        Protocol::EMessageType::SEND_TEXT_MSG,
        encryptedMessageVec
    );

    // update client id in header
    std::copy(m_clientId.begin(), m_clientId.end(), request.begin());

    if (!m_networkManager.send(request)) {
        displayError("Failed to send message.");
        return false;
    }

    std::vector<uint8_t> response = m_networkManager.receive();

    // parse response
    if (response.size() < sizeof(Protocol::ResponseHeader)) {
        displayError("Invalid response from server.");
        return false;
    }

    Protocol::ResponseHeader header;
    std::memcpy(&header, response.data(), sizeof(Protocol::ResponseHeader));

    if (header.code != static_cast<uint16_t>(Protocol::EResponseCode::RESPONSE_MSG_SENT)) {
        displayError("Server responded with an error.");
        return false;
    }

    std::cout << "Message sent successfully to: " << clientName << std::endl;
    return true;
}

bool MessageUClient::sendSymKeyRequest(const std::string& clientName) {
    Client* client = findClientByName(clientName);
    if (!client) {
        displayError("Client not found. Try getting the client list first.");
        return false;
    }

    if (!connectToServer()) {
        displayError("Failed to connect to server.");
        return false;
    }

    // create request (empty content for sym key request)
    std::vector<uint8_t> request = Protocol::packSendMessageRequest(
        client->getID(),
        Protocol::EMessageType::REQUEST_SYM_KEY,
        std::vector<uint8_t>()
    );

    // update client id in header
    std::copy(m_clientId.begin(), m_clientId.end(), request.begin());

    // send request
    if (!m_networkManager.send(request)) {
        displayError("Failed to send symmetric key request.");
        return false;
    }

    // get response
    std::vector<uint8_t> response = m_networkManager.receive();

    // parse response
    if (response.size() < sizeof(Protocol::ResponseHeader)) {
        displayError("Invalid response from server.");
        return false;
    }

    Protocol::ResponseHeader header;
    std::memcpy(&header, response.data(), sizeof(Protocol::ResponseHeader));

    if (header.code != static_cast<uint16_t>(Protocol::EResponseCode::RESPONSE_MSG_SENT)) {
        displayError("Server responded with an error.");
        return false;
    }

    std::cout << "Symmetric key request sent to: " << clientName << std::endl;
    return true;
}

bool MessageUClient::sendSymKey(const std::string& clientName) {
    Client* client = findClientByName(clientName);
    if (!client) {
        displayError("Client not found. Try getting the client list first.");
        return false;
    }

    if (!client->hasPublicKey()) {
        displayError("Public key not available for this client. Request it first.");
        return false;
    }

    if (!client->hasSymmetricKey()) {
        std::vector<uint8_t> symmetricKey(AESWrapper::DEFAULT_KEYLENGTH);

        AESWrapper::GenerateKey(symmetricKey.data(), symmetricKey.size());

        client->setSymmetricKey(symmetricKey);
    }

    // convert from vector to string for RSAPublicWrapper constructor
    std::string publicKeyStr(client->getPublicKey().begin(), client->getPublicKey().end());

    RSAPublicWrapper rsaPublic(publicKeyStr);

    std::string symKeyStr(client->getSymmetricKey().begin(), client->getSymmetricKey().end());

    std::string encryptedKeyStr = rsaPublic.encrypt(symKeyStr);

    std::vector<uint8_t> encryptedKey(encryptedKeyStr.begin(), encryptedKeyStr.end());

    if (!connectToServer()) {
        displayError("Failed to connect to server.");
        return false;
    }

    std::vector<uint8_t> request = Protocol::packSendMessageRequest(
        client->getID(),
        Protocol::EMessageType::SEND_SYM_KEY,
        encryptedKey
    );

    std::copy(m_clientId.begin(), m_clientId.end(), request.begin());

    if (!m_networkManager.send(request)) {
        displayError("Failed to send symmetric key.");
        return false;
    }

    std::vector<uint8_t> response = m_networkManager.receive();

    if (response.size() < sizeof(Protocol::ResponseHeader)) {
        displayError("Invalid response from server.");
        return false;
    }

    Protocol::ResponseHeader header;
    std::memcpy(&header, response.data(), sizeof(Protocol::ResponseHeader));

    if (header.code != static_cast<uint16_t>(Protocol::EResponseCode::RESPONSE_MSG_SENT)) {
        displayError("Server responded with an error.");
        return false;
    }

    std::cout << "Symmetric key sent to: " << clientName << std::endl;
    return true;
}

void MessageUClient::displayMenu() const {
    std::cout << "\nMessageU client at your service." << std::endl;
    std::cout << "110) Register" << std::endl;
    std::cout << "120) Request for clients list" << std::endl;
    std::cout << "130) Request for public key" << std::endl;
    std::cout << "140) Request for waiting messages" << std::endl;
    std::cout << "150) Send a text message" << std::endl;
    std::cout << "151) Send a request for symmetric key" << std::endl;
    std::cout << "152) Send your symmetric key" << std::endl;
    std::cout << "0) Exit client" << std::endl;
    std::cout << "?" << std::endl;
}

void MessageUClient::displayError(const std::string& message) const {
    std::cerr << "Error: " << message << std::endl;
}

void MessageUClient::displayClientsList() const {
    std::cout << "Available clients:" << std::endl;
    std::cout << "----------------" << std::endl;

    if (m_clients.empty()) {
        std::cout << "No clients found." << std::endl;
        return;
    }

    for (const auto& pair : m_clients) {
        std::cout << pair.first << std::endl;
    }
    std::cout << "----------------" << std::endl;
}

void MessageUClient::displayMessage(const Message& message) const {
    // find the client name by id
    std::string clientName = "Unknown";
    for (const auto& pair : m_clients) {
        if (pair.second.getID() == message.getFromClient()) {
            clientName = pair.first;
            break;
        }
    }

    std::cout << "From: " << clientName << std::endl;
    std::cout << "Content: " << std::endl;

    // process the message based on its type
    switch (message.getType()) {
    case Protocol::EMessageType::REQUEST_SYM_KEY: {
        std::cout << "Request for symmetric key" << std::endl;
        break;
    }
    case Protocol::EMessageType::SEND_SYM_KEY: {
        std::cout << "Symmetric key received" << std::endl;
        std::cout << "Symmetric key will be stored for future communication" << std::endl;
        break;
    }
    case Protocol::EMessageType::SEND_TEXT_MSG: {
        const std::vector<uint8_t>* symKey = nullptr;
        for (const auto& pair : m_clients) {
            if (pair.second.getID() == message.getFromClient() && pair.second.hasSymmetricKey()) {
                symKey = &pair.second.getSymmetricKey();
                break;
            }
        }

        if (!symKey) {
            std::cout << "Can't decrypt message" << std::endl;
            break;
        }

        try {
            AESWrapper aes(symKey->data(), symKey->size());

            std::string decryptedText = aes.decrypt(
                reinterpret_cast<const char*>(message.getContent().data()),
                message.getContent().size()
            );

            std::cout << decryptedText << std::endl;
        }
        catch (const std::exception& e) {
            std::cout << "Can't decrypt message" << std::endl;
        }
        break;
    }
    default:
        std::cout << "Unknown message type" << std::endl;
        break;
    }

    std::cout << "-----<EOM>-----" << std::endl;
}

Client* MessageUClient::findClientByName(const std::string& name) {
    auto it = m_clients.find(name);
    if (it != m_clients.end()) {
        return &(it->second);
    }
    return nullptr;
}

std::vector<uint8_t> MessageUClient::getClientIdByName(const std::string& name) {
    auto it = m_clients.find(name);
    if (it != m_clients.end()) {
        return it->second.getID();
    }
    return std::vector<uint8_t>();
}

std::string MessageUClient::getClientNameById(const std::vector<uint8_t>& clientId) {
    for (const auto& pair : m_clients) {
        if (pair.second.getID() == clientId) {
            return pair.first;
        }
    }
    return "Unknown";
}