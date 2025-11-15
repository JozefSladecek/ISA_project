// Projekt: ISA - snmp2otel
// Autor: Jozef Sládeček
// Login: xsladej00
// Dátum: 17.11.2025

#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "SNMP_PacketBuilder.h"
#include "SNMP_client.h"

#define ASN1_SEQUENCE 0x30
#define ASN1_OID      0x06
#define ASN1_NULL     0x05
#define SNMP_GETREQUEST_TAG 0xA0
#define ERROR_STATUS 0x00
#define ERROR_INDEX 0x00

constexpr uint8_t SNMP_v2c_VERSION_ARRAY[3] = {0x02,0x01,0x01};


uint32_t SNMP_PacketBuilder::request_id_counter = 1; // id

uint32_t SNMP_PacketBuilder::get_next_request_id() {
    return request_id_counter++;
}

std::vector<std::string> SNMP_PacketBuilder::fileLoad(const std::string& filename) {
    std::vector<std::string> oids;
    std::ifstream infile(filename);

    if (!infile.is_open()) {
        std::cerr << "Error: Cannot open file '" << filename << "'\n";
        std::cerr << "Make sure the file exists and is readable.\n";
        exit(1);
    }

    std::string line;
    int line_num = 0;
    while (std::getline(infile, line)) {
        line_num++;

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty()) continue;

        // Basic OID validation (starts with digit, contains only digits and dots)
        bool valid = true;
        for (char c : line) {
            if (!std::isdigit(c) && c != '.') {
                valid = false;
                break;
            }
        }

        if (!valid) {
            std::cerr << "Warning: Invalid OID format at line " << line_num
                      << ": '" << line << "' (skipping)\n";
            continue;
        }

        size_t last_dot = line.find_last_of('.');
        if (last_dot == std::string::npos || line.substr(last_dot + 1) != "0") {
            std::cerr << "Warning: OID at line " << line_num
                      << " is not scalar (does not end with .0), skipping\n";
            continue;
        }

        oids.push_back(line);
    }

    if (oids.empty()) {
        std::cerr << "Error: No valid OIDs found in file '" << filename << "'\n";
        exit(1);
    }

    return oids;
}

std::vector<std::vector<uint32_t>> SNMP_PacketBuilder::parse_oids_to_ints(const std::vector<std::string>& oids) {
    std::stringstream ss;
    std::string item;
    std::vector<std::vector<uint32_t>> all_oids_encoded;

    // convertion of array of string arrays to array of int arrays without '.'
    for (const auto& oid : oids) {
        std::stringstream ss(oid);
        std::vector<uint32_t> result; // new result for each oid
        while (std::getline(ss,item,'.')) {
            int num = std::stoi(item);
            result.push_back(static_cast<uint32_t>(num));    // string -> uint
        }
        all_oids_encoded.push_back(result); // array of arrays

    }

    return all_oids_encoded;
}

//https://learn.microsoft.com/sk-sk/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN
std::vector<uint8_t> SNMP_PacketBuilder::encode_oids_to_ber(const std::vector<uint32_t>& oid_array) {
    std::vector<uint8_t> oid_in_ber;

    uint32_t first_byte = oid_array[0]*40 + oid_array[1];
    oid_in_ber.push_back(static_cast<uint8_t>(first_byte));

    for (size_t i = 2; i < oid_array.size(); i++) {
        uint32_t value = oid_array[i];
        std::vector<uint8_t> bytes;
        do {
            uint8_t byte = value & 0x7F;
            bytes.insert(bytes.begin(), byte);
            value >>= 7;
        } while (value > 0);

        for (size_t j = 0; j < bytes.size() - 1; ++j) {
            bytes[j] |= 0x80;
        }

        oid_in_ber.insert(oid_in_ber.end(), bytes.begin(), bytes.end());
    }

    return oid_in_ber;
}

std::vector<std::vector<uint8_t>> SNMP_PacketBuilder::make_varbind(const std::vector<std::vector<uint8_t>>& encoded_oids_array) {
    std::vector<std::vector<uint8_t>> varbinds;
    for (const auto& oid : encoded_oids_array) {
        std::vector<uint8_t> varbind;
        uint32_t oid_lenght = oid.size();
        std::stringstream ss;
        ss << std::hex << std::uppercase << oid_lenght; // make hex value
        varbind.push_back(ASN1_SEQUENCE);
        varbind.push_back(static_cast<uint8_t>(oid_lenght + 4)); // OID + NULL + ASN1 SEQ + ASN1 OID
        varbind.push_back(ASN1_OID);
        varbind.push_back(static_cast<uint8_t>(oid_lenght));
        varbind.insert(varbind.end(), oid.begin(),oid.end()); // OID
        varbind.push_back(0x05);       // NULL type
        varbind.push_back(0x00);

        varbinds.push_back(varbind);

        /// Some PDUs are concerned
        // only with the name of a variable and not its value (e.g., the
        // GetRequest-PDU).  In this case, the value portion of the binding is
        // ignored by the protocol entity.  However, the value portion must
        // still have valid ASN.1 syntax and encoding.  It is recommended that
        // the ASN.1 value NULL be used for the value portion of such bindings.
    }
    return varbinds;


}

std::vector<uint8_t> SNMP_PacketBuilder::make_varbindlist(const std::vector<std::vector<uint8_t>>& varbinds_array) {
    std::vector<uint8_t> varbindlists;

    uint32_t total_length = 0;

    for (const auto& varbind : varbinds_array) {
        total_length += varbind.size();
        std::stringstream ss;
        ss << std::hex << std::uppercase << total_length;
        varbindlists.insert(varbindlists.end(), varbind.begin(),varbind.end());
    }

    std::vector<uint8_t> result;
    result.push_back(ASN1_SEQUENCE);
    result.push_back(static_cast<uint8_t>(total_length));
    result.insert(result.end(), varbindlists.begin(), varbindlists.end());
    return result;
}

std::vector<uint8_t> SNMP_PacketBuilder::make_getrequest_PDU(std::vector<uint8_t> varbindlist) {
    std::vector<uint8_t> getrequest_packet;
    size_t total_length = 6 + 3 + 3 + varbindlist.size(); // PDU structure: Request-ID (tag+len+4bytes=6) + error-status (tag+len+value=3) + error-index (tag+len+value=3) + VarBindList

    getrequest_packet.push_back(SNMP_GETREQUEST_TAG);
    getrequest_packet.push_back(total_length);

    uint32_t req_id = get_next_request_id();
    // request-id 4b = 1
    getrequest_packet.push_back(0x02); // INTEGER
    getrequest_packet.push_back(0x04); // length
    getrequest_packet.push_back((req_id >> 24) & 0xFF);
    getrequest_packet.push_back((req_id >> 16) & 0xFF);
    getrequest_packet.push_back((req_id >> 8) & 0xFF);
    getrequest_packet.push_back(req_id & 0xFF);


    // error-status 1b = 0
    getrequest_packet.push_back(0x02); // INTEGER
    getrequest_packet.push_back(0x01); // length
    getrequest_packet.push_back(0x00);

    // error-index 1b = 0
    getrequest_packet.push_back(0x02); // INTEGER
    getrequest_packet.push_back(0x01); // length
    getrequest_packet.push_back(0x00);
    getrequest_packet.insert(getrequest_packet.end(), varbindlist.begin(), varbindlist.end());

    return getrequest_packet;

}

std::vector<uint8_t> SNMP_PacketBuilder::encode_community_string(const std::string& community) {
    std::vector<uint8_t> encoded;
    encoded.push_back(0x04);  // ASN.1 OCTET STRING tag
    encoded.push_back(static_cast<uint8_t>(community.length()));  // length of string

    for (char c : community) {
        encoded.push_back(static_cast<uint8_t>(c));
    }

    return encoded;
}

std::vector<uint8_t> SNMP_PacketBuilder::make_message(std::vector<uint8_t> getrequest_PDU, const std::string& community) {
    std::vector<uint8_t> message;

    std::vector<uint8_t> community_encoded = encode_community_string(community);

    size_t total_length = sizeof(SNMP_v2c_VERSION_ARRAY) + community_encoded.size() + getrequest_PDU.size();

    message.push_back(ASN1_SEQUENCE);
    message.push_back(total_length);
    message.insert(message.end(), SNMP_v2c_VERSION_ARRAY, SNMP_v2c_VERSION_ARRAY + 3);
    message.insert(message.end(), community_encoded.begin(), community_encoded.end());
    message.insert(message.end(),getrequest_PDU.begin(),getrequest_PDU.end());
    return message;

}
