#include "messageuclient.h"
#include <iostream>

int main() {
    try {
        MessageUClient client;

        if (!client.initialize()) {
            std::cerr << "Failed to initialize client. Exiting." << std::endl;
            return 1;
        }

        client.run();

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}