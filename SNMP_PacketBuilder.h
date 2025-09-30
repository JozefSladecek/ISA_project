//
// Created by jozef on 9/29/25.
//
#pragma once
#include <vector>
#include <string>
#include <cstdint>
#ifndef ISA_SNMP_PACKETBUILDER_H
#define ISA_SNMP_PACKETBUILDER_H


class SNMP_PacketBuilder {
public:
    static std::vector<std::string> fileLoad(const std::string& filename);
    static std::vector<std::vector<uint32_t>> parse_oids_to_ints(const std::vector<std::string>& oids);
    static std::vector<uint8_t> encode_oids_to_ber(const std::vector<uint32_t>& oid_array);
    static std::vector<std::vector<uint8_t>> make_varbind(const std::vector<std::vector<uint8_t>>& encoded_oids_array);
    static std::vector<uint8_t> make_varbindlist(const std::vector<std::vector<uint8_t>>& oid_array);
    static std::vector<uint8_t> make_getrequest_PDU(std::vector<uint8_t> varbindlist);
    static std::vector<uint8_t> make_message(std::vector<uint8_t> getrequest_PDU);
};


#endif //ISA_SNMP_PACKETBUILDER_H