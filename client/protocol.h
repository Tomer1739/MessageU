#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace Protocol {
    //protocol constants
    constexpr uint8_t SERVER_VERSION = 2;
    constexpr size_t CLIENT_ID_SIZE = 16;
    constexpr size_t NAME_SIZE = 255;
    constexpr size_t PUBLIC_KEY_SIZE = 160;
    constexpr size_t HEADER_SIZE = 7;
    constexpr size_t MSG_ID_SIZE = 4;
    constexpr uint8_t MSG_TYPE_MAX = 3;

    //request Codes
    enum class ERequestCode : uint16_t {
        REQUEST_REGISTRATION = 600,
        REQUEST_USERS = 601,
        REQUEST_PUBLIC_KEY = 602,
        REQUEST_SEND_MSG = 603,
        REQUEST_PENDING_MSG = 604
    };

    //response Codes
    enum class EResponseCode : uint16_t {
        RESPONSE_REGISTRATION = 2100,
        RESPONSE_USERS = 2101,
        RESPONSE_PUBLIC_KEY = 2102,
        RESPONSE_MSG_SENT = 2103,
        RESPONSE_PENDING_MSG = 2104,
        RESPONSE_ERROR = 9000
    };

    //message Types
    enum class EMessageType : uint8_t {
        REQUEST_SYM_KEY = 1,
        SEND_SYM_KEY = 2,
        SEND_TEXT_MSG = 3,
    };

#pragma pack(push, 1)
    struct RequestHeader {
        uint8_t clientId[CLIENT_ID_SIZE];
        uint8_t version;
        uint16_t code;
        uint32_t payloadSize;
    };

    struct ResponseHeader {
        uint8_t version;
        uint16_t code;
        uint32_t payloadSize;
    };
#pragma pack(pop)

    //handling protocol data
    std::vector<uint8_t> packRequestHeader(const std::vector<uint8_t>& clientId, uint8_t version, ERequestCode code, uint32_t payloadSize);
    std::vector<uint8_t> packRegistrationRequest(const std::string& name, const std::vector<uint8_t>& publicKey);
    std::vector<uint8_t> packPublicKeyRequest(const std::vector<uint8_t>& clientId);
    std::vector<uint8_t> packSendMessageRequest(const std::vector<uint8_t>& toClientId, EMessageType msgType, const std::vector<uint8_t>& content);

    bool parseResponseHeader(const std::vector<uint8_t>& data, ResponseHeader& header);
    bool parseRegistrationResponse(const std::vector<uint8_t>& data, std::vector<uint8_t>& clientId);

    std::string bytesToHex(const std::vector<uint8_t>& data);
    std::vector<uint8_t> hexToBytes(const std::string& hex);
};