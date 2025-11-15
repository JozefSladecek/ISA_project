// Projekt: ISA - snmp2otel
// Autor: Jozef Sládeček
// Login: xsladej00
// Dátum: 17.11.2025
// https://www.rfc-editor.org/rfc/rfc3416.html#section-3

#include "SNMP_parser.h"

#include <vector>
#include <string>
#include <cstdint>
#include <iostream>

SNMPResponse SNMP_parser::parse_response(const std::vector<uint8_t>& data) {
    read_sequence(data);
    read_length(data);
    SNMPResponse response;

    if (data.size() < 20 || data[0] != 0x30) {
        std::cerr << "[ERROR] Invalid SNMP packet\n";
        return response;
    }
    int32_t version = read_integer(data);
    if (version != 1) {
        std::cerr << "wrong version" << " \n";
        return response;
    }

    std::string com_string = read_octet_string(data);
    response = read_getresponse_pdu(data);

    return response;
}

size_t SNMP_parser::read_length(const std::vector<uint8_t>& data) {
    uint8_t first_byte = data[offset];
    offset++;

    //https://luca.ntop.org/Teaching/Appunti/asn1.html#BER see Length octets

    if (first_byte < 0x80) {
        return first_byte;
    }
    uint32_t length = 0;
    uint8_t num_bytes = first_byte & 0x7F; // lower 7 bytes have number of bytes for lenght
    for (size_t i = 0; i < num_bytes; i++) {
        length = (length << 8) | data[offset++];  // concatenation
    }
    return length;
}

int32_t SNMP_parser::read_integer(const std::vector<uint8_t>& data) {
    uint8_t tag = data[offset];
    if (tag != 0x02) {
        std::cerr << "expected INTEGER";
    }
    offset++;
    size_t length = read_length(data);
    int32_t value = 0;

    for (size_t i = 0; i < length; i++) {
        value = (value << 8) | data[offset++]; // concatenation for value depends on lenght
    }
    return value;
}

SNMPVarbind SNMP_parser::read_single_varbind(const std::vector<uint8_t>& data) {
    SNMPVarbind varbind;

    read_sequence(data);  // varbind SEQUENCE
    read_length(data);

    varbind.oid = read_oid(data);

    varbind.value = read_value(data);


    return varbind;
}

std::string SNMP_parser::read_octet_string(const std::vector<uint8_t>& data) {
    uint8_t tag = data[offset];
    if (tag != 0x04) {
        std::cerr << "SNMP_parser::read_octet_string: expected OCTET STRING" << std::endl;
        return "";
    }
    offset++;
    size_t length = read_length(data);
    std::string com_string;
    for (size_t i = 0; i < length; i++) {
        com_string += static_cast<char>(data[offset++]);
    }

    return com_string;
}

void SNMP_parser::read_sequence(const std::vector<uint8_t>& data) {

    if (data[offset] != 0x30) {
        std::cerr<< "SNMP_parser::read_sequence error" << std::endl;
    }
    offset++;
}

void SNMP_parser::read_object_id(const std::vector<uint8_t>& data) {

    if (data[offset] != 0x06) {
        std::cerr << "SNMP_parser::read_object_id error" << std::endl;
    }
    offset++;
}

SNMPResponse SNMP_parser::read_getresponse_pdu(const std::vector<uint8_t>& data) {
    SNMPResponse pdu;

    uint8_t tag = data[offset++];
    if (tag != 0xa2) {
        std::cerr << "Expected GetResponse PDU (0xA2)\n";
        return pdu;
    }

    read_length(data);

    pdu.request_id = read_integer(data);
    read_integer(data); // err status
    read_integer(data); // err index

    // Varbind list SEQUENCE
    read_sequence(data);
    size_t varbind_list_length = read_length(data);
    size_t varbind_list_end = offset + varbind_list_length;

    // all varbinds
    while (offset < varbind_list_end) {
        SNMPVarbind vb = read_single_varbind(data);
        pdu.varbinds.push_back(vb);
    }

    return pdu;
}

std::vector<uint32_t> SNMP_parser::read_oid(const std::vector<uint8_t>& data) {
    std::vector<uint32_t> oid;
    read_object_id(data);
    size_t oid_length = read_length(data);
    size_t oid_end = offset + oid_length;

    uint8_t first_byte = data[offset++];

    uint32_t first = first_byte / 40;
    uint32_t second = first_byte % 40;

    oid.push_back(first);
    oid.push_back(second);
    while (offset < oid_end) {
        uint32_t value = 0;
        uint8_t byte;
        do {
            byte = data[offset++];
            value = (value << 7) | (byte & 0x7F); // shift left
        } while (byte & 0x80); // msb is set to 1
        oid.push_back(value);
    }
    return oid;
}

std::string SNMP_parser::read_value(const std::vector<uint8_t>& data) {
    uint8_t tag = data[offset];

    switch (tag) {
        case 0x02: { // INTEGER
            int32_t val = read_integer(data);
            return std::to_string(val);
        }
        case 0x04: { // OCTET STRING
            return read_octet_string(data);
        }

        case 0x05: { // NULL
            offset++; // tag skip
            read_length(data);
            return "NULL";
        }

        case 0x43: {  // TimeTicks
            offset++;
            size_t length = read_length(data);
            uint32_t timeticks = 0;
            for (size_t i = 0; i < length; i++) {
                timeticks = (timeticks << 8) | data[offset++];
            }
            return std::to_string(timeticks);
        }

        case 0x41: {  // Counter32
            offset++;
            size_t length = read_length(data);
            uint32_t counter = 0;
            for (size_t i = 0; i < length; i++) {
                counter = (counter << 8) | data[offset++];
            }
            return std::to_string(counter);
        }

        case 0x42: {  // Gauge32
            offset++;
            size_t length = read_length(data);
            uint32_t gauge = 0;
            for (size_t i = 0; i < length; i++) {
                gauge = (gauge << 8) | data[offset++];
            }
            return std::to_string(gauge);
        }
        default:
            std::cerr << "Unsupported value tag: 0x"
                      << std::hex << static_cast<int>(tag) << std::dec
                      << std::endl;
            offset++;
            return "";
    }

}