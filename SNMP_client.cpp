#include "SNMP_client.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <iomanip>

#define SNMP_port 161

SNMP_client::SNMP_client(const std::string& ip)
    : target_ip(resolveIP(ip)), port(SNMP_port)
{
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("Error while opening socket");
        socket_fd = -1;
    }
}

int SNMP_client::SNMP_send(const std::vector<uint8_t>& packet) {
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, target_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid IP address\n";
        close(socket_fd);
        socket_fd = -1;
        return 1;
    }

    int sent = sendto(socket_fd, packet.data(), packet.size(), 0,
                     (struct sockaddr*)&server_addr, sizeof(server_addr));

    if (sent < 0) {
        std::cerr << "Error while sending\n";
        close(socket_fd);
        socket_fd = -1;
        return 1;
    }
    return 0;
}

int SNMP_client::SMNP_recieve() {
    uint8_t buffer[1024];
    socklen_t addr_len = sizeof(server_addr);

    int received = recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                            (struct sockaddr*)&server_addr, &addr_len);

    if (received < 0) {
        std::cerr << "Error while receiving\n";
        close(socket_fd);
        return 1;
    }

    std::cout << "Received response (" << received << " bytes):\n";
    for (int i = 0; i < received; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)buffer[i] << " ";
        if ((i+1) % 16 == 0) std::cout << "\n";
    }
    std::cout << "\n";
    return 0;
}

SNMP_client::~SNMP_client() {
    if (socket_fd >= 0) close(socket_fd);
}

std::string SNMP_client::resolveIP(const std::string &target) {
    struct addrinfo hints{}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int status = getaddrinfo(target.c_str(), NULL, &hints, &result);
    if (status != 0) return "";

    char ipStr[INET_ADDRSTRLEN];
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)result->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, sizeof(ipStr));
    freeaddrinfo(result);
    return ipStr;
}
