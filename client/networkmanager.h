#pragma once
#include <string>
#include <vector>
#include <memory>
#include <boost/asio.hpp>
#include "protocol.h"

class NetworkManager {
public:
    NetworkManager();
    virtual ~NetworkManager();

    bool connect(const std::string& serverAddress, int serverPort);

    bool send(const std::vector<uint8_t>& data);

    std::vector<uint8_t> receive();

    bool isConnected() const;

    void disconnect();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};