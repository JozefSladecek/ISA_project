// Projekt: ISA - snmp2otel
// Autor: Jozef Sládeček
// Login: xsladej00
// Dátum: 17.11.2025

#ifndef ISA_SNMP_PARSER_H
#define ISA_SNMP_PARSER_H

#include <vector>
#include <string>
#include <cstdint>

struct SNMPVarbind {
    std::vector<uint32_t> oid;
    std::string value;
};

struct SNMPResponse {
    uint32_t request_id;
    std::vector<SNMPVarbind> varbinds;
};



class SNMP_parser {
public:
    SNMP_parser() : offset(0) {}

    // Parses entire SNMP response
    SNMPResponse parse_response(const std::vector<uint8_t>& data);

private:
    size_t offset;

    // Utility functions that consume data and advance offset
    size_t read_length(const std::vector<uint8_t>& data);
    int32_t read_integer(const std::vector<uint8_t>& data);
    SNMPVarbind read_single_varbind(const std::vector<uint8_t>& data);
    std::string read_octet_string(const std::vector<uint8_t>& data);
    void read_sequence(const std::vector<uint8_t>& data);
    SNMPResponse read_getresponse_pdu(const std::vector<uint8_t>& data);
    void read_object_id(const std::vector<uint8_t>& data);
    std::vector<uint32_t> read_oid(const std::vector<uint8_t>& data);
    std::string read_value(const std::vector<uint8_t>& data);

};

#endif //ISA_SNMP_PARSER_H
