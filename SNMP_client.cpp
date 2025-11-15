// Projekt: ISA - snmp2otel
// Autor: Jozef Sládeček
// Login: xsladej00
// Dátum: 17.11.2025
#include "SNMP_client.h"

#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <iomanip>

#define SNMP_port 161

SNMP_client::SNMP_client(const std::string& ip, int timeout, int port)
    : target_ip(resolveIP(ip)), port(port)
{
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        std::cerr << "Error: Cannot create UDP socket: " << strerror(errno) << "\n";
        exit(1);
    }

    set_receive_timeout(timeout);
}


void SNMP_client::set_receive_timeout(int ms) {
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "Error: Cannot set socket timeout: " << strerror(errno) << "\n";
        close(socket_fd);
        socket_fd = -1;
        exit(1);
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

std::vector<uint8_t> SNMP_client::SNMP_receive() {
    std::vector<uint8_t> buffer(1024);
    socklen_t addr_len = sizeof(server_addr);

    int received = recvfrom(socket_fd, buffer.data(), buffer.size(), 0,
                            (struct sockaddr*)&server_addr, &addr_len);

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            std::cerr << "Timeout: No SNMP response received.\n";
        } else {
            perror("Error while receiving");
        }
        return {};
    }

    buffer.resize(received);

    return buffer;
}


SNMP_client::~SNMP_client() {
    if (socket_fd >= 0) close(socket_fd);
}

// if adress in dns format return ip else return ip
std::string SNMP_client::resolveIP(const std::string &target) {
    struct addrinfo hints{};
    struct addrinfo *result;

    hints.ai_family = AF_INET;      // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP

    int status = getaddrinfo(target.c_str(), NULL, &hints, &result);
    if (status != 0) {
        std::cerr << "Error while getaddrinfo()\n";
        return ""; // empty string means err
    }

    char ipStr[INET_ADDRSTRLEN];

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)result->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, sizeof(ipStr)); // to string

    freeaddrinfo(result);
    return ipStr;
}
