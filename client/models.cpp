#include "models.h"

// client implementation
Client::Client(const std::vector<uint8_t>& id, const std::string& name)
    : m_id(id), m_name(name) {
}

Client::Client(const std::vector<uint8_t>& id, const std::string& name, const std::vector<uint8_t>& publicKey)
    : m_id(id), m_name(name), m_publicKey(publicKey) {
}

bool Client::isValid() const {
    if (m_id.empty() || m_id.size() != Protocol::CLIENT_ID_SIZE) {
        return false;
    }

    if (m_name.empty() || m_name.size() >= Protocol::NAME_SIZE) {
        return false;
    }

    return true;
}

// message implementation
Message::Message(const std::vector<uint8_t>& toClient,
    const std::vector<uint8_t>& fromClient,
    Protocol::EMessageType type,
    const std::vector<uint8_t>& content)
    : m_toClient(toClient), m_fromClient(fromClient), m_type(type), m_content(content) {
}

bool Message::isValid() const {
    if (m_toClient.empty() || m_toClient.size() != Protocol::CLIENT_ID_SIZE) {
        return false;
    }

    if (m_fromClient.empty() || m_fromClient.size() != Protocol::CLIENT_ID_SIZE) {
        return false;
    }

    // check message type according to protocol
    uint8_t typeValue = static_cast<uint8_t>(m_type);
    if (typeValue < 1 || typeValue > Protocol::MSG_TYPE_MAX) {
        return false;
    }

    return true;
}