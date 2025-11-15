// Projekt: ISA - snmp2otel
// Autor: [Jozef Sládeček]
// Login: xsladej00
// Unit tests

#include <iostream>
#include <cassert>
#include <vector>
#include <cstdint>
#include <fstream>

#include "../SNMP_parser.h"

#include "../SNMP_PacketBuilder.h"

#include "../OTELExporter.h"


// macros
#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "Running " #name "... "; \
    test_##name(); \
    std::cout << "PASSED\n"; \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::cerr << "\nFAIL at line " << __LINE__ << ": " << #a << " != " << #b << "\n"; \
        std::cerr << "  Expected: " << (b) << "\n"; \
        std::cerr << "  Got: " << (a) << "\n"; \
        exit(1); \
    } \
} while(0)

#define ASSERT_EQ_HEX(a, b) do { \
    if ((a) != (b)) { \
        std::cerr << "\nFAIL at line " << __LINE__ << ": " << #a << " != " << #b << "\n"; \
        std::cerr << "  Expected: 0x" << std::hex << (int)(b) << std::dec << "\n"; \
        std::cerr << "  Got: 0x" << std::hex << (int)(a) << std::dec << "\n"; \
        exit(1); \
    } \
} while(0)

//=============================================================================
// TEST 1: File loading - valid OIDs
//=============================================================================
TEST(file_load_valid) {
    // Create temporary test file
    std::ofstream outfile("/tmp/test_oids_valid.txt");
    outfile << "1.3.6.1.2.1.1.1.0\n";
    outfile << "1.3.6.1.2.1.1.3.0\n";
    outfile << "1.3.6.1.2.1.1.5.0\n";
    outfile.close();

    std::vector<std::string> oids = SNMP_PacketBuilder::fileLoad("/tmp/test_oids_valid.txt");

    ASSERT_EQ(oids.size(), 3);
    ASSERT_EQ(oids[0], "1.3.6.1.2.1.1.1.0");
    ASSERT_EQ(oids[1], "1.3.6.1.2.1.1.3.0");
    ASSERT_EQ(oids[2], "1.3.6.1.2.1.1.5.0");

    // Cleanup
    std::remove("/tmp/test_oids_valid.txt");
}
//=============================================================================
// TEST 2: File loading - with comments and empty lines
//=============================================================================
TEST(file_load_with_comments) {
    std::ofstream outfile("/tmp/test_oids_comments.txt");
    outfile << "# System OIDs\n";
    outfile << "1.3.6.1.2.1.1.1.0\n";
    outfile << "\n";  // empty line
    outfile << "# Uptime\n";
    outfile << "1.3.6.1.2.1.1.3.0\n";
    outfile.close();

    std::vector<std::string> oids = SNMP_PacketBuilder::fileLoad("/tmp/test_oids_comments.txt");

    // Should only load 2 OIDs (comments and empty lines ignored)
    ASSERT_EQ(oids.size(), 2);
    ASSERT_EQ(oids[0], "1.3.6.1.2.1.1.1.0");
    ASSERT_EQ(oids[1], "1.3.6.1.2.1.1.3.0");

    std::remove("/tmp/test_oids_comments.txt");
}

//=============================================================================
// TEST 3: Basic OID to ber encoding (1.3.6.1.2.1.1.1.0)
//=============================================================================
TEST(oid_encoding_basic) {
    // OID: 1.3.6.1.2.1.1.1.0
    std::vector<uint32_t> oid = {1, 3, 6, 1, 2, 1, 1, 1, 0};

    std::vector<uint8_t> encoded = SNMP_PacketBuilder::encode_oids_to_ber(oid);

    // expected result:
    // 1.3 → 0x2B (1*40 + 3 = 43)
    // 6 → 0x06
    // 1 → 0x01
    // 2 → 0x02
    // 1 → 0x01
    // 1 → 0x01
    // 1 → 0x01
    // 0 → 0x00

    std::vector<uint8_t> expected = {0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};

    ASSERT_EQ(encoded.size(), expected.size());

    for (size_t i = 0; i < expected.size(); i++) {
        ASSERT_EQ_HEX(encoded[i], expected[i]);
    }
}

//=============================================================================
// TEST 4: OID encoding with large numbers (Base-128)
// Example from Microsoft: 1.3.6.1.4.1.311.21.20
//=============================================================================
TEST(oid_encoding_large_numbers) {
    // OID: 1.3.6.1.4.1.311.21.20
    // Contains number 311 which is greater than 127
    std::vector<uint32_t> oid = {1, 3, 6, 1, 4, 1, 311, 21, 20};

    std::vector<uint8_t> encoded = SNMP_PacketBuilder::encode_oids_to_ber(oid);

    // Expected result:
    // 1.3 → 0x2B (1*40 + 3 = 43)
    // 6 → 0x06
    // 1 → 0x01
    // 4 → 0x04
    // 1 → 0x01
    // 311 → Base-128 encoding
    //   311 ÷ 128 = 2 remainder 55
    //   2 | 0x80 = 0x82 (MSB=1, not last byte)
    //   55 = 0x37
    //   → 0x82 0x37
    // 21 → 0x15
    // 20 → 0x14

    std::vector<uint8_t> expected = {
        0x2B,       // 1.3
        0x06,       // 6
        0x01,       // 1
        0x04,       // 4
        0x01,       // 1
        0x82, 0x37, // 311 in Base-128
        0x15,       // 21
        0x14        // 20
    };

    ASSERT_EQ(encoded.size(), expected.size());

    for (size_t i = 0; i < expected.size(); i++) {
        ASSERT_EQ_HEX(encoded[i], expected[i]);
    }
}

//=============================================================================
// TEST 5: OID string parsing to integers
//=============================================================================
TEST(oid_parsing_single) {
    // Parse single OID string "1.3.6.1.2.1.1.1.0"
    std::vector<std::string> oids = {"1.3.6.1.2.1.1.1.0"};

    auto parsed = SNMP_PacketBuilder::parse_oids_to_ints(oids);

    // Expected: one vector with 9 elements
    ASSERT_EQ(parsed.size(), 1);
    ASSERT_EQ(parsed[0].size(), 9);

    // Check each number
    ASSERT_EQ(parsed[0][0], 1);
    ASSERT_EQ(parsed[0][1], 3);
    ASSERT_EQ(parsed[0][2], 6);
    ASSERT_EQ(parsed[0][3], 1);
    ASSERT_EQ(parsed[0][4], 2);
    ASSERT_EQ(parsed[0][5], 1);
    ASSERT_EQ(parsed[0][6], 1);
    ASSERT_EQ(parsed[0][7], 1);
    ASSERT_EQ(parsed[0][8], 0);
}

//=============================================================================
// TEST 6: URL parsing - host and port extraction
//=============================================================================
TEST(url_parsing_with_port) {
    // Parse "http://localhost:9999/v1/metrics"
    std::string url = "http://localhost:9999/v1/metrics";

    auto parsed = OTELExporter::parse_host_port(url);

    // Expected: host="localhost", port=9999
    ASSERT_EQ(parsed.host, "localhost");
    ASSERT_EQ(parsed.port, 9999);
}

//=============================================================================
// TEST 7: Multiple OID string parsing
//=============================================================================
TEST(oid_parsing_multiple) {
    // Parse multiple OID strings
    std::vector<std::string> oids = {
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.3.0",
        "1.3.6.1.2.1.1.5.0"
    };

    auto parsed = SNMP_PacketBuilder::parse_oids_to_ints(oids);

    // Expected: 3 vectors
    ASSERT_EQ(parsed.size(), 3);

    // Check first OID
    ASSERT_EQ(parsed[0].size(), 9);
    ASSERT_EQ(parsed[0][0], 1);
    ASSERT_EQ(parsed[0][8], 0);

    // Check second OID
    ASSERT_EQ(parsed[1].size(), 9);
    ASSERT_EQ(parsed[1][7], 3);

    // Check third OID
    ASSERT_EQ(parsed[2].size(), 9);
    ASSERT_EQ(parsed[2][7], 5);
}

//=============================================================================
// TEST 8: Multiple OID string parsing
//=============================================================================
TEST(oid_encoding_128_boundary) {
    std::vector<uint32_t> oid = {1, 3, 6, 1, 128};

    auto encoded = SNMP_PacketBuilder::encode_oids_to_ber(oid);

    std::vector<uint8_t> expected = {
        0x2B,       // 1.3
        0x06,       // 6
        0x01,       // 1
        0x81, 0x00  // 128 boundary
    };

    ASSERT_EQ(encoded.size(), expected.size());
    for (size_t i = 0; i < expected.size(); i++)
        ASSERT_EQ_HEX(encoded[i], expected[i]);
}

//=============================================================================
// TEST 9: VarBind creation - single OID
//=============================================================================
TEST(varbind_single_oid) {
    // Encode OID 1.3.6.1.2.1.1.1.0
    std::vector<uint32_t> oid = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    std::vector<uint8_t> encoded = SNMP_PacketBuilder::encode_oids_to_ber(oid);

    std::vector<std::vector<uint8_t>> oids_array = {encoded};
    std::vector<std::vector<uint8_t>> varbinds = SNMP_PacketBuilder::make_varbind(oids_array);

    // Should return 1 varbind
    ASSERT_EQ(varbinds.size(), 1);

    // VarBind structure:
    // 0x30 = SEQUENCE tag
    // length
    // 0x06 = OID tag
    // oid_length
    // ... OID bytes ...
    // 0x05 = NULL tag
    // 0x00 = NULL length

    ASSERT_EQ_HEX(varbinds[0][0], 0x30);  // SEQUENCE
    ASSERT_EQ_HEX(varbinds[0][2], 0x06);  // OID tag

    // Check NULL at end
    size_t len = varbinds[0].size();
    ASSERT_EQ_HEX(varbinds[0][len-2], 0x05);  // NULL tag
    ASSERT_EQ_HEX(varbinds[0][len-1], 0x00);  // NULL length
}

//=============================================================================
// TEST 10: VarBind creation - multiple OIDs
//=============================================================================
TEST(varbind_multiple_oids) {
    std::vector<uint32_t> oid1 = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    std::vector<uint32_t> oid2 = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    std::vector<uint32_t> oid3 = {1, 3, 6, 1, 2, 1, 1, 5, 0};

    std::vector<uint8_t> enc1 = SNMP_PacketBuilder::encode_oids_to_ber(oid1);
    std::vector<uint8_t> enc2 = SNMP_PacketBuilder::encode_oids_to_ber(oid2);
    std::vector<uint8_t> enc3 = SNMP_PacketBuilder::encode_oids_to_ber(oid3);

    std::vector<std::vector<uint8_t>> oids_array = {enc1, enc2, enc3};
    std::vector<std::vector<uint8_t>> varbinds = SNMP_PacketBuilder::make_varbind(oids_array);

    // Should return 3 varbinds
    ASSERT_EQ(varbinds.size(), 3);

    // Each should start with SEQUENCE
    ASSERT_EQ_HEX(varbinds[0][0], 0x30);
    ASSERT_EQ_HEX(varbinds[1][0], 0x30);
    ASSERT_EQ_HEX(varbinds[2][0], 0x30);
}

//=============================================================================
// TEST 11: VarBindList creation - single varbind
//=============================================================================
TEST(varbindlist_single) {
    // Create one varbind
    std::vector<uint32_t> oid = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    std::vector<uint8_t> encoded = SNMP_PacketBuilder::encode_oids_to_ber(oid);
    std::vector<std::vector<uint8_t>> oids_array = {encoded};
    std::vector<std::vector<uint8_t>> varbinds = SNMP_PacketBuilder::make_varbind(oids_array);

    // Make varbindlist
    std::vector<uint8_t> varbindlist = SNMP_PacketBuilder::make_varbindlist(varbinds);

    // VarBindList structure:
    // 0x30 = SEQUENCE tag
    // length
    // ... varbinds ...

    ASSERT_EQ_HEX(varbindlist[0], 0x30);  // SEQUENCE tag

    // Length should be total length of all varbinds
    uint8_t expected_length = varbinds[0].size();
    ASSERT_EQ(varbindlist[1], expected_length);
}

//=============================================================================
// TEST 12: VarBindList creation - multiple varbinds
//=============================================================================
TEST(varbindlist_multiple) {
    std::vector<uint32_t> oid1 = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    std::vector<uint32_t> oid2 = {1, 3, 6, 1, 2, 1, 1, 3, 0};

    std::vector<uint8_t> enc1 = SNMP_PacketBuilder::encode_oids_to_ber(oid1);
    std::vector<uint8_t> enc2 = SNMP_PacketBuilder::encode_oids_to_ber(oid2);

    std::vector<std::vector<uint8_t>> oids_array = {enc1, enc2};
    std::vector<std::vector<uint8_t>> varbinds = SNMP_PacketBuilder::make_varbind(oids_array);

    std::vector<uint8_t> varbindlist = SNMP_PacketBuilder::make_varbindlist(varbinds);

    // Should start with SEQUENCE
    ASSERT_EQ_HEX(varbindlist[0], 0x30);

    // Length should be sum of both varbinds
    size_t expected_length = varbinds[0].size() + varbinds[1].size();
    ASSERT_EQ(varbindlist[1], static_cast<uint8_t>(expected_length));

    // Total size = tag + length + varbinds
    ASSERT_EQ(varbindlist.size(), 2 + expected_length);
}

//=============================================================================
// TEST 13: GetRequest PDU structure
//=============================================================================
TEST(getrequest_pdu_structure) {
    // Create simple varbindlist
    std::vector<uint32_t> oid = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    std::vector<uint8_t> encoded = SNMP_PacketBuilder::encode_oids_to_ber(oid);
    std::vector<std::vector<uint8_t>> oids_array = {encoded};
    std::vector<std::vector<uint8_t>> varbinds = SNMP_PacketBuilder::make_varbind(oids_array);
    std::vector<uint8_t> varbindlist = SNMP_PacketBuilder::make_varbindlist(varbinds);

    // Make GetRequest PDU
    std::vector<uint8_t> pdu = SNMP_PacketBuilder::make_getrequest_PDU(varbindlist);

    // PDU structure:
    // 0xA0 = GetRequest tag
    // length
    // 0x02 0x04 = INTEGER (4 bytes) for Request ID
    // ... 4 bytes request ID ...
    // 0x02 0x01 0x00 = error-status (0)
    // 0x02 0x01 0x00 = error-index (0)
    // ... varbindlist ...

    ASSERT_EQ_HEX(pdu[0], 0xA0);  // GetRequest tag

    // Check Request ID (should be INTEGER)
    ASSERT_EQ_HEX(pdu[2], 0x02);  // INTEGER tag
    ASSERT_EQ_HEX(pdu[3], 0x04);  // 4 bytes

    // Check error-status
    ASSERT_EQ_HEX(pdu[8], 0x02);  // INTEGER tag
    ASSERT_EQ_HEX(pdu[9], 0x01);  // 1 byte
    ASSERT_EQ_HEX(pdu[10], 0x00); // value = 0

    // Check error-index
    ASSERT_EQ_HEX(pdu[11], 0x02);  // INTEGER tag
    ASSERT_EQ_HEX(pdu[12], 0x01);  // 1 byte
    ASSERT_EQ_HEX(pdu[13], 0x00);  // value = 0
}

//=============================================================================
// TEST 14: GetRequest PDU - Request ID increments
//=============================================================================
TEST(getrequest_pdu_request_id) {
    std::vector<uint32_t> oid = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    std::vector<uint8_t> encoded = SNMP_PacketBuilder::encode_oids_to_ber(oid);
    std::vector<std::vector<uint8_t>> oids_array = {encoded};
    std::vector<std::vector<uint8_t>> varbinds = SNMP_PacketBuilder::make_varbind(oids_array);
    std::vector<uint8_t> varbindlist = SNMP_PacketBuilder::make_varbindlist(varbinds);

    // Make first PDU
    uint32_t req_id_1 = SNMP_PacketBuilder::request_id_counter;
    std::vector<uint8_t> pdu1 = SNMP_PacketBuilder::make_getrequest_PDU(varbindlist);

    // Make second PDU
    uint32_t req_id_2 = SNMP_PacketBuilder::request_id_counter;
    std::vector<uint8_t> pdu2 = SNMP_PacketBuilder::make_getrequest_PDU(varbindlist);

    // Request IDs should be different
    // Extract Request ID from PDU (bytes 4-7 after tag and length)
    uint32_t extracted_id_1 = (pdu1[4] << 24) | (pdu1[5] << 16) | (pdu1[6] << 8) | pdu1[7];
    uint32_t extracted_id_2 = (pdu2[4] << 24) | (pdu2[5] << 16) | (pdu2[6] << 8) | pdu2[7];

    ASSERT_EQ(extracted_id_1, req_id_1);
    ASSERT_EQ(extracted_id_2, req_id_2);
    ASSERT_EQ(extracted_id_2, extracted_id_1 + 1);
}

//=============================================================================
// TEST 15: Community string encoding
//=============================================================================
TEST(community_string_encoding) {
    // Test encoding of "test12"
    std::vector<uint8_t> encoded = SNMP_PacketBuilder::encode_community_string("test12");

    // Expected: 0x04 (OCTET STRING tag), 0x06 (length=6), "public"
    std::vector<uint8_t> expected = {
        0x04,                           // OCTET STRING tag
        0x06,                           // length = 6
        't', 'e', 's', 't', '1', '2'   // "public"
    };

    ASSERT_EQ(encoded.size(), expected.size());

    for (size_t i = 0; i < expected.size(); i++) {
        ASSERT_EQ_HEX(encoded[i], expected[i]);
    }
}

//=============================================================================
// TEST 16: Full SNMP message structure
//=============================================================================
TEST(snmp_message_structure) {
    std::vector<uint32_t> oid = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    std::vector<uint8_t> encoded = SNMP_PacketBuilder::encode_oids_to_ber(oid);
    std::vector<std::vector<uint8_t>> oids_array = {encoded};
    std::vector<std::vector<uint8_t>> varbinds = SNMP_PacketBuilder::make_varbind(oids_array);
    std::vector<uint8_t> varbindlist = SNMP_PacketBuilder::make_varbindlist(varbinds);
    std::vector<uint8_t> pdu = SNMP_PacketBuilder::make_getrequest_PDU(varbindlist);

    // Make full message with community "public"
    std::vector<uint8_t> message = SNMP_PacketBuilder::make_message(pdu, "public");

    // Message structure:
    // 0x30 = SEQUENCE tag
    // length
    // 0x02 0x01 0x01 = version (SNMPv2c = 1)
    // 0x04 0x06 'p' 'u' 'b' 'l' 'i' 'c' = community
    // ... PDU ...

    ASSERT_EQ_HEX(message[0], 0x30);  // SEQUENCE

    // Check version
    ASSERT_EQ_HEX(message[2], 0x02);  // INTEGER tag
    ASSERT_EQ_HEX(message[3], 0x01);  // 1 byte
    ASSERT_EQ_HEX(message[4], 0x01);  // value = 1 (SNMPv2c)

    // Check community string
    ASSERT_EQ_HEX(message[5], 0x04);  // OCTET STRING tag
    ASSERT_EQ_HEX(message[6], 0x06);  // length = 6
    ASSERT_EQ(message[7], 'p');
    ASSERT_EQ(message[8], 'u');
    ASSERT_EQ(message[9], 'b');
    ASSERT_EQ(message[10], 'l');
    ASSERT_EQ(message[11], 'i');
    ASSERT_EQ(message[12], 'c');

    // PDU should start at byte 13
    ASSERT_EQ_HEX(message[13], 0xA0);  // GetRequest tag
}

//=============================================================================
// END OF PACKET_BUILDER TESTS |
//=============================================================================


//=============================================================================
// PARSER TESTS
//=============================================================================

//=============================================================================
// TEST 17: SNMP Response Parsing - Integer value
//=============================================================================
TEST(snmp_parser_integer) {
    std::vector<uint8_t> response = {
        0x30, 0x2A,                                   // SEQUENCE (42)
        0x02, 0x01, 0x01,                             // Version (3)
        0x04, 0x06, 'p','u','b','l','i','c',         // Community (8)
        0xA2, 0x1D,                                   // GetResponse PDU (29)
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,          // Request ID (6)
        0x02, 0x01, 0x00,                             // Error status (3)
        0x02, 0x01, 0x00,                             // Error index (3)
        0x30, 0x0F,                                   // VarBindList (15)
        0x30, 0x0D,                                   // VarBind (13)
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00,  // OID (10)
        0x02, 0x01, 0x48                              // INTEGER: 72 (3)
    };

    SNMP_parser parser;
    SNMPResponse parsed = parser.parse_response(response);

    ASSERT_EQ(parsed.request_id, 1);
    ASSERT_EQ(parsed.varbinds.size(), 1);
    ASSERT_EQ(parsed.varbinds[0].value, "72");
    ASSERT_EQ(parsed.varbinds[0].oid.size(), 9);
}

//=============================================================================
// TEST 18: SNMP Response Parsing - TimeTicks value
//=============================================================================
TEST(snmp_parser_timeticks) {
    std::vector<uint8_t> response = {
        0x30, 0x2D,                                   // SEQUENCE (45)
        0x02, 0x01, 0x01,                             // Version (3)
        0x04, 0x06, 'p','u','b','l','i','c',         // Community (8)
        0xA2, 0x20,                                   // GetResponse PDU (32)
        0x02, 0x04, 0x00, 0x00, 0x00, 0x02,          // Request ID (6)
        0x02, 0x01, 0x00,                             // Error status (3)
        0x02, 0x01, 0x00,                             // Error index (3)
        0x30, 0x12,                                   // VarBindList (18)
        0x30, 0x10,                                   // VarBind (16)
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00,  // OID (10)
        0x43, 0x04, 0x00, 0x01, 0xE2, 0x40           // TimeTicks: 123456 (6)
    };

    SNMP_parser parser;
    SNMPResponse parsed = parser.parse_response(response);

    ASSERT_EQ(parsed.request_id, 2);
    ASSERT_EQ(parsed.varbinds.size(), 1);
    ASSERT_EQ(parsed.varbinds[0].value, "123456");
}

//=============================================================================
// TEST 19: SNMP Response Parsing - Gauge32 value
//=============================================================================
TEST(snmp_parser_gauge32) {
    std::vector<uint8_t> response = {
        0x30, 0x30,                                   // SEQUENCE (48)
        0x02, 0x01, 0x01,                             // Version (3)
        0x04, 0x06, 'p','u','b','l','i','c',         // Community (8)
        0xA2, 0x23,                                   // GetResponse PDU (35)
        0x02, 0x04, 0x00, 0x00, 0x00, 0x03,          // Request ID (6)
        0x02, 0x01, 0x00,                             // Error status (3)
        0x02, 0x01, 0x00,                             // Error index (3)
        0x30, 0x15,                                   // VarBindList (21)
        0x30, 0x13,                                   // VarBind (19)
        0x06, 0x0B, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0A, 0x01, 0x00, // OID (13)
        0x42, 0x04, 0x00, 0x0F, 0x42, 0x40           // Gauge32: 1000000 (6)
    };

    SNMP_parser parser;
    SNMPResponse parsed = parser.parse_response(response);

    ASSERT_EQ(parsed.request_id, 3);
    ASSERT_EQ(parsed.varbinds.size(), 1);
    ASSERT_EQ(parsed.varbinds[0].value, "1000000");
}

//=============================================================================
// TEST 20: SNMP Response Parsing - Counter32 value
//=============================================================================
TEST(snmp_parser_counter32) {
    std::vector<uint8_t> response = {
        0x30, 0x30,                                   // SEQUENCE (48)
        0x02, 0x01, 0x01,                             // Version (3)
        0x04, 0x06, 'p','u','b','l','i','c',         // Community (8)
        0xA2, 0x23,                                   // GetResponse PDU (35)
        0x02, 0x04, 0x00, 0x00, 0x00, 0x04,          // Request ID (6)
        0x02, 0x01, 0x00,                             // Error status (3)
        0x02, 0x01, 0x00,                             // Error index (3)
        0x30, 0x15,                                   // VarBindList (21)
        0x30, 0x13,                                   // VarBind (19)
        0x06, 0x0B, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0B, 0x01, 0x00, // OID (13)
        0x41, 0x04, 0x00, 0x07, 0xA1, 0x20           // Counter32: 500000 (6)
    };

    SNMP_parser parser;
    SNMPResponse parsed = parser.parse_response(response);

    ASSERT_EQ(parsed.request_id, 4);
    ASSERT_EQ(parsed.varbinds.size(), 1);
    ASSERT_EQ(parsed.varbinds[0].value, "500000");
}

//=============================================================================
// TEST 21: SNMP Response Parsing - OCTET STRING value
//=============================================================================
TEST(snmp_parser_octet_string) {
    std::vector<uint8_t> response = {
        0x30, 0x30,                                   // SEQUENCE (48)
        0x02, 0x01, 0x01,                             // Version (3)
        0x04, 0x06, 'p','u','b','l','i','c',         // Community (8)
        0xA2, 0x23,                                   // GetResponse PDU (35)
        0x02, 0x04, 0x00, 0x00, 0x00, 0x05,          // Request ID (6)
        0x02, 0x01, 0x00,                             // Error status (3)
        0x02, 0x01, 0x00,                             // Error index (3)
        0x30, 0x15,                                   // VarBindList (21)
        0x30, 0x13,                                   // VarBind (19)
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00,  // OID (10)
        0x04, 0x08, 'T','e','s','t','H','o','s','t'  // OCTET STRING: "TestHost" (10)
    };

    SNMP_parser parser;
    SNMPResponse parsed = parser.parse_response(response);

    ASSERT_EQ(parsed.request_id, 5);
    ASSERT_EQ(parsed.varbinds.size(), 1);
    ASSERT_EQ(parsed.varbinds[0].value, "TestHost");
}

//=============================================================================
// TEST 22: SNMP Response Parsing - Multiple varbinds
//=============================================================================
TEST(snmp_parser_multiple_varbinds) {
    std::vector<uint8_t> response = {
        0x30, 0x37,                                   // SEQUENCE (55)
        0x02, 0x01, 0x01,                             // Version (3)
        0x04, 0x06, 'p','u','b','l','i','c',         // Community (8)
        0xA2, 0x2A,                                   // GetResponse PDU (42)
        0x02, 0x04, 0x00, 0x00, 0x00, 0x06,          // Request ID (6)
        0x02, 0x01, 0x00,                             // Error status (3)
        0x02, 0x01, 0x00,                             // Error index (3)
        0x30, 0x1C,                                   // VarBindList (28)
        // VarBind 1
        0x30, 0x0D,                                   // VarBind (13)
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00,
        0x02, 0x01, 0x48,                             // INTEGER: 72
        // VarBind 2
        0x30, 0x0D,                                   // VarBind (13)
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00,
        0x02, 0x01, 0x64                              // INTEGER: 100
    };

    SNMP_parser parser;
    SNMPResponse parsed = parser.parse_response(response);

    ASSERT_EQ(parsed.request_id, 6);
    ASSERT_EQ(parsed.varbinds.size(), 2);
    ASSERT_EQ(parsed.varbinds[0].value, "72");
    ASSERT_EQ(parsed.varbinds[1].value, "100");
}

//=============================================================================
// TEST 23: SNMP Response Parsing - Large INTEGER (4 bytes)
//=============================================================================
TEST(snmp_parser_large_integer) {
    std::vector<uint8_t> response = {
        0x30, 0x2C,                                   // SEQUENCE (44)
        0x02, 0x01, 0x01,                             // Version (3)
        0x04, 0x06, 'p','u','b','l','i','c',         // Community (8)
        0xA2, 0x1F,                                   // GetResponse PDU (31)
        0x02, 0x04, 0x00, 0x00, 0x00, 0x07,          // Request ID (6)
        0x02, 0x01, 0x00,                             // Error status (3)
        0x02, 0x01, 0x00,                             // Error index (3)
        0x30, 0x11,                                   // VarBindList (17)
        0x30, 0x0F,                                   // VarBind (15)
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00,  // OID (10)
        0x02, 0x04, 0x01, 0x00, 0x00, 0x00           // INTEGER: 16777216 (6) - 4 byte value
    };

    SNMP_parser parser;
    SNMPResponse parsed = parser.parse_response(response);

    ASSERT_EQ(parsed.request_id, 7);
    ASSERT_EQ(parsed.varbinds.size(), 1);
    ASSERT_EQ(parsed.varbinds[0].value, "16777216");
}

//=============================================================================
// TEST 24: SNMP Response Parsing - NULL value
//=============================================================================
TEST(snmp_parser_null_value) {
    std::vector<uint8_t> response = {
        0x30, 0x2A,                                   // SEQUENCE (42)
        0x02, 0x01, 0x01,                             // Version (3)
        0x04, 0x06, 'p','u','b','l','i','c',         // Community (8)
        0xA2, 0x1D,                                   // GetResponse PDU (29) ← PRIDANÉ!
        0x02, 0x04, 0x00, 0x00, 0x00, 0x08,          // Request ID (6)
        0x02, 0x01, 0x00,                             // Error status (3)
        0x02, 0x01, 0x00,                             // Error index (3)
        0x30, 0x0E,                                   // VarBindList (14)
        0x30, 0x0C,                                   // VarBind (12)
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00,  // OID (10)
        0x05, 0x00                                    // NULL (2)
    };

    SNMP_parser parser;
    SNMPResponse parsed = parser.parse_response(response);

    ASSERT_EQ(parsed.request_id, 8);
    ASSERT_EQ(parsed.varbinds.size(), 1);
    ASSERT_EQ(parsed.varbinds[0].value, "NULL");
}





//=============================================================================
// MAIN - run tests
//=============================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "  ISA snmp2otel - Unit Tests\n";
    std::cout << "========================================\n\n";

    int passed = 0;
    int total = 24;

    try {
        RUN_TEST(file_load_valid);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(file_load_with_comments);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(oid_encoding_basic);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(oid_encoding_large_numbers);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(oid_encoding_128_boundary);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(oid_parsing_single);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(oid_parsing_multiple);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(community_string_encoding);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(varbind_single_oid);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(varbind_multiple_oids);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(varbindlist_single);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(varbindlist_multiple);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(getrequest_pdu_structure);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(getrequest_pdu_request_id);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(snmp_message_structure);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(url_parsing_with_port);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(snmp_parser_integer);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(snmp_parser_timeticks);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(snmp_parser_gauge32);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(snmp_parser_counter32);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(snmp_parser_octet_string);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(snmp_parser_multiple_varbinds);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(snmp_parser_large_integer);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    try {
        RUN_TEST(snmp_parser_null_value);
        passed++;
    } catch (...) {
        std::cerr << "Test crashed!\n";
    }

    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << "/" << total << " tests passed\n";
    std::cout << "========================================\n";

    return (passed == total) ? 0 : 1;
}