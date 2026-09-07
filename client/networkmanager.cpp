#include "networkmanager.h"
#include <iostream>
#include <thread>
#include <chrono>

class NetworkManager::Impl {
public:
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket;
    bool connected;

    // constructor initializes socket with io_context
    Impl() : io_context(), socket(io_context), connected(false) {}
};

NetworkManager::NetworkManager() : m_impl(std::make_unique<Impl>()) {
}

NetworkManager::~NetworkManager() {
    disconnect();
}

bool NetworkManager::connect(const std::string& serverAddress, int serverPort) {
    try {
        if (m_impl->connected) {
            disconnect();
        }

        m_impl->io_context.restart();

        boost::asio::ip::tcp::resolver resolver(m_impl->io_context);
        auto endpoints = resolver.resolve(serverAddress, std::to_string(serverPort));

        // connect to the server with timeout
        boost::system::error_code ec;
        boost::asio::connect(m_impl->socket, endpoints, ec);

        if (ec) {
            std::cerr << "Connection error: " << ec.message() << std::endl;
            return false;
        }

        m_impl->connected = true;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Connection error: " << e.what() << std::endl;
        m_impl->connected = false;
        return false;
    }
}

void NetworkManager::disconnect() {
    if (m_impl->connected && m_impl->socket.is_open()) {
        try {
            boost::system::error_code ec;
            m_impl->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            m_impl->socket.close(ec);
        }
        catch (const std::exception& e) {
            std::cerr << "Disconnect error: " << e.what() << std::endl;
        }
        m_impl->connected = false;
    }
}

bool NetworkManager::send(const std::vector<uint8_t>& data) {
    if (!m_impl->connected || !m_impl->socket.is_open()) {
        return false;
    }

    try {
        boost::system::error_code ec;
        boost::asio::write(m_impl->socket, boost::asio::buffer(data), ec);

        if (ec) {
            std::cerr << "Send error: " << ec.message() << std::endl;
            m_impl->connected = false;
            return false;
        }
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Send error: " << e.what() << std::endl;
        m_impl->connected = false;
        return false;
    }
}

std::vector<uint8_t> NetworkManager::receive() {
    std::vector<uint8_t> response;

    if (!m_impl->connected || !m_impl->socket.is_open()) {
        return response;
    }

    try {
        // read the header first (7 bytes)
        std::vector<uint8_t> headerBuffer(Protocol::HEADER_SIZE);

        // use error code for error handling
        boost::system::error_code ec;
        size_t bytesRead = boost::asio::read(m_impl->socket,
            boost::asio::buffer(headerBuffer),
            ec);

        if (ec || bytesRead != Protocol::HEADER_SIZE) {
            throw std::runtime_error("Failed to read response header");
        }

        // parse the header to get payload size
        Protocol::ResponseHeader header;
        std::memcpy(&header, headerBuffer.data(), Protocol::HEADER_SIZE);

        response = std::move(headerBuffer);

        // read the payload
        if (header.payloadSize > 0) {
            std::vector<uint8_t> payloadBuffer(header.payloadSize);
            bytesRead = boost::asio::read(m_impl->socket,
                boost::asio::buffer(payloadBuffer),
                ec);

            if (ec || bytesRead != header.payloadSize) {
                throw std::runtime_error("Failed to read complete payload");
            }

            // append payload to response
            response.insert(response.end(), payloadBuffer.begin(), payloadBuffer.end());
        }

        return response;
    }
    catch (const std::exception& e) {
        std::cerr << "Receive error: " << e.what() << std::endl;
        m_impl->connected = false;
        return std::vector<uint8_t>();
    }
}

bool NetworkManager::isConnected() const {
    return m_impl->connected && m_impl->socket.is_open();
}