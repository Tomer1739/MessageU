#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include "networkmanager.h"
#include "models.h"
#include "RSAWrapper.h"

class MessageUClient {
public:
    MessageUClient();
    ~MessageUClient();

    bool initialize();
    void run();

private:
    std::string m_serverAddress;
    int m_serverPort;

    std::string m_clientName;
    std::vector<uint8_t> m_clientId;
    bool m_isRegistered;
    bool m_isRunning;

    std::unique_ptr<RSAPrivateWrapper> m_rsaPrivate;

    NetworkManager m_networkManager;

    std::map<std::string, Client> m_clients;

    //helper methods
    bool loadServerInfo();
    bool loadClientInfo();
    bool saveClientInfo(const std::string& name, const std::vector<uint8_t>& clientId, const std::string& privateKey);
    bool connectToServer();

    //protocol handlers
    bool registerClient();
    bool requestClientsList();
    bool requestPublicKey(const std::string& clientName);
    bool requestPendingMessages();
    bool sendTextMessage(const std::string& clientName, const std::string& messageText);
    bool sendSymKeyRequest(const std::string& clientName);
    bool sendSymKey(const std::string& clientName);

    //UI methods
    void displayMenu() const;
    void displayError(const std::string& message) const;
    void displayClientsList() const;
    void displayMessage(const Message& message) const;

    //find and get client
    Client* findClientByName(const std::string& name);
    std::vector<uint8_t> getClientIdByName(const std::string& name);
    std::string getClientNameById(const std::vector<uint8_t>& clientId);
};