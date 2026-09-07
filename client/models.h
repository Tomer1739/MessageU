#pragma once
#include <string>
#include <vector>
#include <ctime>
#include "protocol.h"

class Client {
public:
    Client() = default;
    Client(const std::vector<uint8_t>& id, const std::string& name);
    Client(const std::vector<uint8_t>& id, const std::string& name, const std::vector<uint8_t>& publicKey);

    // get methods
    const std::vector<uint8_t>& getID() const { return m_id; }
    const std::string& getName() const { return m_name; }
    const std::vector<uint8_t>& getPublicKey() const { return m_publicKey; }
    const std::vector<uint8_t>& getSymmetricKey() const { return m_symmetricKey; }

    // set methods
    void setPublicKey(const std::vector<uint8_t>& publicKey) { m_publicKey = publicKey; }
    void setSymmetricKey(const std::vector<uint8_t>& symmetricKey) { m_symmetricKey = symmetricKey; }

    // validation
    bool isValid() const;
    bool hasPublicKey() const { return !m_publicKey.empty(); }
    bool hasSymmetricKey() const { return !m_symmetricKey.empty(); }

private:
    std::vector<uint8_t> m_id;
    std::string m_name;
    std::vector<uint8_t> m_publicKey;
    std::vector<uint8_t> m_symmetricKey;
};

class Message {
public:
    Message() = default;
    Message(const std::vector<uint8_t>& toClient,
        const std::vector<uint8_t>& fromClient,
        Protocol::EMessageType type,
        const std::vector<uint8_t>& content);

    // get methods
    uint32_t getID() const { return m_id; }
    const std::vector<uint8_t>& getToClient() const { return m_toClient; }
    const std::vector<uint8_t>& getFromClient() const { return m_fromClient; }
    Protocol::EMessageType getType() const { return m_type; }
    const std::vector<uint8_t>& getContent() const { return m_content; }

    // set methods
    void setID(uint32_t id) { m_id = id; }

    // validation
    bool isValid() const;

private:
    uint32_t m_id = 0;
    std::vector<uint8_t> m_toClient;
    std::vector<uint8_t> m_fromClient;
    Protocol::EMessageType m_type;
    std::vector<uint8_t> m_content;
};