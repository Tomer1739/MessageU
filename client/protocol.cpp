#include "protocol.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace Protocol {

    std::vector<uint8_t> packRequestHeader(const std::vector<uint8_t>& clientId, uint8_t version, ERequestCode code, uint32_t payloadSize) {
        std::vector<uint8_t> result(sizeof(RequestHeader));
        RequestHeader* header = reinterpret_cast<RequestHeader*>(result.data());

        // copy client ID
        if (clientId.size() == CLIENT_ID_SIZE) {
            std::copy(clientId.begin(), clientId.end(), header->clientId);
        }
        else {
            std::fill(header->clientId, header->clientId + CLIENT_ID_SIZE, 0);
            if (!clientId.empty()) {
                std::copy(clientId.begin(), clientId.begin() + std::min(clientId.size(), static_cast<size_t>(CLIENT_ID_SIZE)), header->clientId);
            }
        }

        header->version = version;
        header->code = static_cast<uint16_t>(code);
        header->payloadSize = payloadSize;

        return result;
    }

    std::vector<uint8_t> packRegistrationRequest(const std::string& name, const std::vector<uint8_t>& publicKey) {
        std::vector<uint8_t> emptyClientId(CLIENT_ID_SIZE, 0);

        uint32_t payloadSize = NAME_SIZE + PUBLIC_KEY_SIZE;

        std::vector<uint8_t> result = packRequestHeader(emptyClientId, 1, ERequestCode::REQUEST_REGISTRATION, payloadSize);

        std::vector<uint8_t> nameBuffer(NAME_SIZE, 0);
        std::copy(name.begin(), name.end(), nameBuffer.begin());

        std::vector<uint8_t> publicKeyBuffer(PUBLIC_KEY_SIZE, 0);
        std::copy(publicKey.begin(), publicKey.begin() + std::min(publicKey.size(), static_cast<size_t>(PUBLIC_KEY_SIZE)), publicKeyBuffer.begin());

        result.insert(result.end(), nameBuffer.begin(), nameBuffer.end());
        result.insert(result.end(), publicKeyBuffer.begin(), publicKeyBuffer.end());

        return result;
    }

    std::vector<uint8_t> packPublicKeyRequest(const std::vector<uint8_t>& clientId) {
        std::vector<uint8_t> myClientId(CLIENT_ID_SIZE, 0);
        if (!clientId.empty()) {
            std::copy(clientId.begin(), clientId.begin() + std::min(clientId.size(), static_cast<size_t>(CLIENT_ID_SIZE)), myClientId.begin());
        }

        std::vector<uint8_t> result = packRequestHeader(myClientId, 1, ERequestCode::REQUEST_PUBLIC_KEY, CLIENT_ID_SIZE);

        result.insert(result.end(), myClientId.begin(), myClientId.end());

        return result;
    }

    std::vector<uint8_t> packSendMessageRequest(const std::vector<uint8_t>& toClientId, EMessageType msgType, const std::vector<uint8_t>& content) {
        std::vector<uint8_t> myClientId(CLIENT_ID_SIZE, 0);

        uint32_t payloadSize = CLIENT_ID_SIZE + sizeof(uint8_t) + sizeof(uint32_t) + content.size();

        std::vector<uint8_t> result = packRequestHeader(myClientId, 1, ERequestCode::REQUEST_SEND_MSG, payloadSize);

        result.insert(result.end(), toClientId.begin(), toClientId.begin() + std::min(toClientId.size(), static_cast<size_t>(CLIENT_ID_SIZE)));

        result.push_back(static_cast<uint8_t>(msgType));

        uint32_t contentSize = static_cast<uint32_t>(content.size());
        result.push_back(contentSize & 0xFF);
        result.push_back((contentSize >> 8) & 0xFF);
        result.push_back((contentSize >> 16) & 0xFF);
        result.push_back((contentSize >> 24) & 0xFF);

        result.insert(result.end(), content.begin(), content.end());

        return result;
    }

    bool parseResponseHeader(const std::vector<uint8_t>& data, ResponseHeader& header) {
        if (data.size() < sizeof(ResponseHeader)) {
            return false;
        }

        std::memcpy(&header, data.data(), sizeof(ResponseHeader));
        return true;
    }

    bool parseRegistrationResponse(const std::vector<uint8_t>& data, std::vector<uint8_t>& clientId) {
        ResponseHeader header;
        if (!parseResponseHeader(data, header)) {
            return false;
        }

        if (header.code != static_cast<uint16_t>(EResponseCode::RESPONSE_REGISTRATION) ||
            data.size() < sizeof(ResponseHeader) + CLIENT_ID_SIZE) {
            return false;
        }

        clientId.resize(CLIENT_ID_SIZE);
        std::copy(data.begin() + sizeof(ResponseHeader),
            data.begin() + sizeof(ResponseHeader) + CLIENT_ID_SIZE,
            clientId.begin());

        return true;
    }

    std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (const auto& byte : data) {
            ss << std::setw(2) << static_cast<int>(byte);
        }

        return ss.str();
    }

    std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;

        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }

        return bytes;
    }
}