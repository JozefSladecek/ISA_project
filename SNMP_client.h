//
// Created by jozef on 9/29/25.
//

#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <netinet/in.h>

#ifndef ISA_SNMP_CLIENT_H
#define ISA_SNMP_CLIENT_H


class SNMP_client {
public:
    SNMP_client(const std::string& ip);
    int SNMP_send(const std::vector<uint8_t>& packet);
    std::vector<uint8_t> SNMP_receive();
    ~SNMP_client();

private:
    std::string target_ip;
    int socket_fd;
    int port;
    struct sockaddr_in server_addr{};
    static std::string resolveIP(const std::string &target);
    static void print_answer(const std::vector<uint8_t>& buffer);
};



#endif //ISA_SNMP_CLIENT_H