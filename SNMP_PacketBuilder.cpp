//
// Created by jozef on 9/29/25.
//

#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include "SNMP_PacketBuilder.h"
#include "SNMP_client.h"

#define ASN1_SEQUENCE 0x30
#define ASN1_OID      0x06
#define ASN1_NULL     0x05
#define SNMP_GETREQUEST_TAG 0xA0
#define ERROR_STATUS 0x00
#define ERROR_INDEX 0x00

#include "SNMP_PacketBuilder.h"


std::vector<std::string> SNMP_PacketBuilder::fileLoad(const std::string& filename) {
    std::vector<std::string> oids;
    std::ifstream infile(filename);

    if (!infile.is_open()) {
        std::cerr << "Error: Cannot open file " << filename << "\n";
        return oids;
    }

    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty() || line[0] == '#') continue;
        oids.push_back(line);
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
            //std::cout << item << "\n";
        }
        all_oids_encoded.push_back(result); // array of arrays

    }

    return all_oids_encoded;
}

std::vector<uint8_t> SNMP_PacketBuilder::encode_oids_to_ber(const std::vector<uint32_t>& oid_array) {
    std::vector<uint8_t> oid_in_ber;

    uint32_t first_byte = oid_array[0]*40 + oid_array[1];
    oid_in_ber.push_back(static_cast<uint8_t>(first_byte));

    for (int i = 2; i < oid_array.size(); i++) {
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
        varbind.push_back(static_cast<uint8_t>(oid_lenght + 2)); // OID + NULL
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
        //std::cout << "OID length in hex: " << ss.str() << "\n";
    }
    return varbinds;


    // int oid_index = 1;
    // for (const auto& ber_oid : encoded_oids_array) {
    //     std::cout << "OID " << oid_index++ << ": ";
    //     for (auto b : ber_oid) {
    //         std::cout << "0x"
    //                   << std::hex << std::setw(2) << std::setfill('0')
    //                   << static_cast<int>(b) << " ";
    //     }
    //     std::cout << std::dec << "\n";
    // }
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
    varbindlists.insert(varbindlists.begin() + 1, static_cast<uint8_t>(total_length));
    return varbindlists;
}

std::vector<uint8_t> SNMP_PacketBuilder::make_getrequest_PDU(std::vector<uint8_t> varbindlist) {
    std::vector<uint8_t> getrequest_packet;
    auto total_length = static_cast<uint8_t>(varbindlist.size() + 3); // id + err +err

    getrequest_packet.push_back(SNMP_GETREQUEST_TAG);
    getrequest_packet.push_back(total_length);
    getrequest_packet.push_back(ERROR_STATUS); //todo id counter meanwhile 0

    getrequest_packet.push_back(ERROR_STATUS); // err status
    getrequest_packet.push_back(ERROR_INDEX); // err index
    getrequest_packet.insert(getrequest_packet.end(), varbindlist.begin(), varbindlist.end());

    return getrequest_packet;

}
