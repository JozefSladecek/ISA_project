// Projekt: ISA - snmp2otel
// Autor: Jozef Sládeček
// Login: xsladej00
// Dátum: 17.11.2025
#pragma once
#include <vector>
#include <string>
#include <netinet/in.h>

#ifndef ISA_SNMP_CLIENT_H
#define ISA_SNMP_CLIENT_H


class SNMP_client {
public:
    SNMP_client(const std::string& ip, int timeout, int port);
    int SNMP_send(const std::vector<uint8_t>& packet);
    std::vector<uint8_t> SNMP_receive();
    ~SNMP_client();

    void set_receive_timeout(int ms);
    static std::string resolveIP(const std::string &target);


private:
    std::string target_ip;
    int socket_fd;
    int port;
    struct sockaddr_in server_addr{};
};



#endif //ISA_SNMP_CLIENT_H