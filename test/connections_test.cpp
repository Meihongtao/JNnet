#include <iostream>
#include <vector>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

void connectToServer(int clientNum) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket creation failed");
        return;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(7788);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("connect failed");
        close(sockfd);
        return;
    }

    std::cout << "Client " << clientNum << " connected to the server." << std::endl;

    // Add your client-server communication logic here
    sleep(100);

    close(sockfd);
}

int main() {
    const int numClients = 100000; // Set the desired number of clients

    std::vector<std::thread> threads;

    for (int i = 1; i <= numClients; ++i) {
        threads.emplace_back(connectToServer, i);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    return 0;
}
