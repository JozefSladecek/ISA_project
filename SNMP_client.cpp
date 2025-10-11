#include "SNMP_client.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <iomanip>

#define SNMP_port 161

SNMP_client::SNMP_client(const std::string& ip,int timeout)
    : target_ip(resolveIP(ip)), port(SNMP_port)
{
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("Error while opening socket");
        socket_fd = -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        perror("Error while setting socket timeout");
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
    print_answer(buffer);

    return buffer;
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



// AI GENERATED
void SNMP_client::print_answer(const std::vector<uint8_t>& buffer) {
    size_t idx = 0;
    auto received = buffer.size();

    std::cout << "\n=== SNMP Response Debug ===" << std::endl;
    std::cout << "Received " << received << " bytes\n" << std::endl;

    // Raw hex dump
    std::cout << "Raw Hex Dump:" << std::endl;
    for (size_t i = 0; i < received; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(buffer[i]) << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::dec << "\n" << std::endl;

    // SNMP packet začína SEQUENCE
    if (buffer[idx] != 0x30) {
        std::cerr << "Error: Expected SEQUENCE (0x30), got 0x"
                  << std::hex << (int)buffer[idx] << std::dec << std::endl;
        return;
    }
    std::cout << "[" << idx << "] SEQUENCE (0x30)" << std::endl;
    idx++;

    // Dĺžka SEQUENCE
    int seq_len = buffer[idx++];
    if (seq_len & 0x80) {
        int len_bytes = seq_len & 0x7F;
        seq_len = 0;
        for (int i = 0; i < len_bytes; i++) {
            seq_len = (seq_len << 8) | buffer[idx++];
        }
    }
    std::cout << "    Length: " << seq_len << " bytes\n" << std::endl;

    // SNMP Version (INTEGER)
    if (buffer[idx] == 0x02) {
        idx++;
        int ver_len = buffer[idx++];
        int version = 0;
        for (int i = 0; i < ver_len; i++) {
            version = (version << 8) | buffer[idx++];
        }
        std::cout << "[" << (idx - ver_len - 2) << "] Version: " << version;
        if (version == 0) std::cout << " (SNMPv1)";
        else if (version == 1) std::cout << " (SNMPv2c)";
        std::cout << std::endl;
    }

    // Community String (OCTET STRING)
    if (buffer[idx] == 0x04) {
        idx++;
        int comm_len = buffer[idx++];
        std::cout << "[" << (idx - 2) << "] Community: \"";
        for (int i = 0; i < comm_len; i++) {
            std::cout << buffer[idx++];
        }
        std::cout << "\"" << std::endl;
    }

    // PDU Type (Get-Response = 0xA2)
    std::cout << "\n[" << idx << "] PDU Type: 0x" << std::hex
              << (int)buffer[idx] << std::dec;
    if (buffer[idx] == 0xA0) std::cout << " (GetRequest)";
    else if (buffer[idx] == 0xA1) std::cout << " (GetNextRequest)";
    else if (buffer[idx] == 0xA2) std::cout << " (GetResponse)";
    else if (buffer[idx] == 0xA3) std::cout << " (SetRequest)";
    std::cout << std::endl;
    idx++;

    // PDU Length
    int pdu_len = buffer[idx++];
    if (pdu_len & 0x80) {
        int len_bytes = pdu_len & 0x7F;
        pdu_len = 0;
        for (int i = 0; i < len_bytes; i++) {
            pdu_len = (pdu_len << 8) | buffer[idx++];
        }
    }
    std::cout << "    PDU Length: " << pdu_len << " bytes" << std::endl;

    // Request ID
    if (buffer[idx] == 0x02) {
        idx++;
        int req_len = buffer[idx++];
        int req_id = 0;
        for (int i = 0; i < req_len; i++) {
            req_id = (req_id << 8) | buffer[idx++];
        }
        std::cout << "[" << (idx - req_len - 2) << "] Request ID: " << req_id << std::endl;
    }

    // Error Status
    if (buffer[idx] == 0x02) {
        idx++;
        int err_len = buffer[idx++];
        int err_status = 0;
        for (int i = 0; i < err_len; i++) {
            err_status = (err_status << 8) | buffer[idx++];
        }
        std::cout << "[" << (idx - err_len - 2) << "] Error Status: " << err_status;
        if (err_status == 0) std::cout << " (noError)";
        else if (err_status == 1) std::cout << " (tooBig)";
        else if (err_status == 2) std::cout << " (noSuchName)";
        else if (err_status == 3) std::cout << " (badValue)";
        else if (err_status == 4) std::cout << " (readOnly)";
        else if (err_status == 5) std::cout << " (genErr)";
        std::cout << std::endl;
    }

    // Error Index
    if (buffer[idx] == 0x02) {
        idx++;
        int err_idx_len = buffer[idx++];
        int err_index = 0;
        for (int i = 0; i < err_idx_len; i++) {
            err_index = (err_index << 8) | buffer[idx++];
        }
        std::cout << "[" << (idx - err_idx_len - 2) << "] Error Index: " << err_index << std::endl;
    }

    // Variable Bindings (SEQUENCE)
    std::cout << "\n[" << idx << "] Variable Bindings:" << std::endl;
    if (buffer[idx] == 0x30) {
        idx++;
        int vb_len = buffer[idx++];
        if (vb_len & 0x80) {
            int len_bytes = vb_len & 0x7F;
            vb_len = 0;
            for (int i = 0; i < len_bytes; i++) {
                vb_len = (vb_len << 8) | buffer[idx++];
            }
        }

        int vb_count = 0;
        int vb_end = idx + vb_len;

        while (idx < vb_end && idx < received) {
            vb_count++;
            std::cout << "\n  [VarBind #" << vb_count << "]" << std::endl;

            // VarBind SEQUENCE
            if (buffer[idx] == 0x30) {
                idx++;
                int vb_item_len = buffer[idx++];

                // OID (OBJECT IDENTIFIER)
                if (buffer[idx] == 0x06) {
                    idx++;
                    int oid_len = buffer[idx++];
                    std::cout << "    OID: ";

                    if (oid_len > 0) {
                        // První byte obsahuje první dva identifikátory
                        int first = buffer[idx] / 40;
                        int second = buffer[idx] % 40;
                        std::cout << first << "." << second;
                        idx++;

                        // Zbylé identifikátory
                        for (int i = 1; i < oid_len; i++) {
                            int val = 0;
                            do {
                                val = (val << 7) | (buffer[idx] & 0x7F);
                                if (!(buffer[idx] & 0x80)) {
                                    std::cout << "." << val;
                                    idx++;
                                    break;
                                }
                                idx++;
                            } while (idx < received);
                        }
                    }
                    std::cout << std::endl;
                }

                // Value
                std::cout << "    Value Type: 0x" << std::hex << (int)buffer[idx] << std::dec;
                uint8_t val_type = buffer[idx++];

                if (val_type == 0x02) std::cout << " (INTEGER)";
                else if (val_type == 0x04) std::cout << " (OCTET STRING)";
                else if (val_type == 0x06) std::cout << " (OID)";
                else if (val_type == 0x40) std::cout << " (IP Address)";
                else if (val_type == 0x41) std::cout << " (Counter32)";
                else if (val_type == 0x42) std::cout << " (Gauge32)";
                else if (val_type == 0x43) std::cout << " (TimeTicks)";
                else if (val_type == 0x05) std::cout << " (NULL)";
                std::cout << std::endl;

                int val_len = buffer[idx++];
                std::cout << "    Value: ";

                if (val_type == 0x02 || val_type == 0x41 || val_type == 0x42 || val_type == 0x43) {
                    // INTEGER/Counter/Gauge/TimeTicks
                    int value = 0;
                    for (int i = 0; i < val_len; i++) {
                        value = (value << 8) | buffer[idx++];
                    }
                    std::cout << value;
                } else if (val_type == 0x04) {
                    // OCTET STRING
                    std::cout << "\"";
                    for (int i = 0; i < val_len; i++) {
                        char c = buffer[idx++];
                        if (c >= 32 && c <= 126) std::cout << c;
                        else std::cout << ".";
                    }
                    std::cout << "\"";
                } else if (val_type == 0x40) {
                    // IP Address
                    for (int i = 0; i < val_len; i++) {
                        std::cout << (int)buffer[idx++];
                        if (i < val_len - 1) std::cout << ".";
                    }
                } else if (val_type == 0x05) {
                    // NULL
                    idx += val_len;
                    std::cout << "NULL";
                } else {
                    // Unknown - vypíš hex
                    for (int i = 0; i < val_len; i++) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                                  << (int)buffer[idx++] << " ";
                    }
                    std::cout << std::dec;
                }
                std::cout << std::endl;
            }
        }
    }

    std::cout << "\n=== End of SNMP Response ===" << std::endl;
}