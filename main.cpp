#include <iostream>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <netdb.h>
#include <bitset>
#include <sstream>
#include <iomanip>

#include <csignal>
#include <atomic>
#include <chrono>
#include <thread>


#include "OTELExporter.h"
#include "SNMP_PacketBuilder.h"
#include "SNMP_client.h"
#include "SNMP_parser.h"

//todo check about static classes and helper functions

//https://learn.microsoft.com/sk-sk/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN

// test packet
std::vector<uint8_t> testpacket = {
    0x30, 0x29,             // Sequence, length 41
    0x02, 0x01, 0x01,       // Version: v2c (1)
    0x04, 0x06, 'p','u','b','l','i','c', // Community: "public"
    0xa0, 0x1c,             // GetRequest PDU, length 28
    0x02, 0x04, 0x00,0x00,0x00,0x01,     // Request ID: 1
    0x02, 0x01, 0x00,       // Error status: 0
    0x02, 0x01, 0x00,       // Error index: 0
    0x30, 0x0e,             // Varbind list, length 14
    0x30, 0x0c,             // Varbind, length 12
    0x06, 0x08, 0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00, // OID 1.3.6.1.2.1.1.1.0
    0x05, 0x00              // Value: NULL
};

std::atomic<bool> keep_running(true);

void signal_handler(int signal) {
    if (signal == SIGINT) {
        keep_running = false;
    }
}

#define SNMP_port 161
constexpr int OID_FIRST_BYTE_FACTOR = 40;

#define ASN1_SEQUENCE 0x30
#define ASN1_OID      0x06
#define ASN1_NULL     0x05
#define SNMP_GETREQUEST_TAG 0xA0

#define ERROR_STATUS 0x00
#define ERROR_INDEX 0x00

void print_packet(const std::vector<uint8_t>& packet) {
    std::cout << "Packet (" << packet.size() << " bytes):\n";
    for (size_t i = 0; i < packet.size(); ++i) {
        std::cout << "0x"
                  << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(packet[i]) << " ";
        if ((i + 1) % 16 == 0) std::cout << "\n"; // nový riadok po 16 bajtoch
    }
    std::cout << std::dec << "\n"; // späť na desiatkovú sústavu
}
//// args parser

struct Config {
    std::string target;
    std::string community = "public";
    std::string oids_file;
    std::string endpoint;
    int interval = 10;
    int retries = 2;
    int timeout = 1000;
    int port = 161;
    bool verbose = false;
    int opt;
};

Config parseArgs(int argc, char* argv[]) {
    Config config;
    int opt;

    while ((opt = getopt(argc, argv, "t:C:o:e:i:r:T:p:v")) != -1) {
        switch(opt) {
            case 't': config.target = optarg; break;
            case 'C': config.community = optarg; break;
            case 'o': config.oids_file = optarg; break;
            case 'e': config.endpoint = optarg; break;
            case 'i': config.interval = std::stoi(optarg); break;  // stoi = string -> int
            case 'r': config.retries = std::stoi(optarg); break;
            case 'T': config.timeout = std::stoi(optarg); break;
            case 'p': config.port = std::stoi(optarg); break;
            case 'v': config.verbose = true; break;
            default:
                std::cerr << "Unknown option\n";
                exit(1);
        }
    }
    return config;
}

//// args parser


// if adress in dns format return ip else return ip
std::string resolveIP(const std::string &target) {
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


int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);

    Config config = parseArgs(argc, argv);


    std::vector<std::string> oids = SNMP_PacketBuilder::fileLoad("oids.txt");


    std::vector<std::vector<uint32_t>> all_oids_int;


    all_oids_int = SNMP_PacketBuilder::parse_oids_to_ints(oids);

    std::vector<std::vector<uint8_t>> all_oids_encoded;

    for (const auto& oid : all_oids_int) {
        all_oids_encoded.push_back(SNMP_PacketBuilder::encode_oids_to_ber(oid));
    }

    int oid_index = 1;
    for (const auto& ber_oid : all_oids_encoded) {
        std::cout << "OID " << oid_index++ << ": ";
        for (auto b : ber_oid) {
            std::cout << "0x"
                      << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(b) << " ";
        }
        std::cout << std::dec << "\n";
    }

    std::vector<std::vector<uint8_t>> varbinds = SNMP_PacketBuilder::make_varbind(all_oids_encoded);

    std::vector<uint8_t> varbinds_list = SNMP_PacketBuilder::make_varbindlist(varbinds);

    // std::vector<uint8_t> getrequestPDU = SNMP_PacketBuilder::make_getrequest_PDU(varbinds_list);
    //
    //
    // std::vector<uint8_t> packet_to_send = SNMP_PacketBuilder::make_message(getrequestPDU);

    int index = 1;
    for (const auto& vb : varbinds) {
        std::cout << "Varbind " << index++ << ": ";
        for (auto b : vb) {
            std::cout << "0x"
                      << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(b) << " ";
        }
        std::cout << std::dec << "\n";
    }

    std::cout << "Varbind list: ";
    for (auto b : varbinds_list) {
        std::cout << "0x"
                  << std::hex << std::setw(2) << std::setfill('0')
                  << (int)b << " ";
    }
    std::cout << std::dec << "\n";



   // print_packet(packet_to_send);
    //print_packet(testpacket);

    std::string ip = resolveIP(config.target);

    //SNMP_client client(ip, config.timeout);
    //SNMP_parser parser;
    OTELExporter exporter(ip, 4318, config.verbose);

    std::vector<uint8_t> received_packet;


    SNMP_client client(ip,config.timeout);

   // int retries = 0;
   // bool received = false;

    while (keep_running) {
        SNMP_parser parser;
        bool received = false;
        auto start_time = std::chrono::steady_clock::now();
        //SNMP_PacketBuilder::get_next_request_id();
        uint32_t current_req_id = SNMP_PacketBuilder::request_id_counter;
        std::vector<uint8_t> getrequestPDU = SNMP_PacketBuilder::make_getrequest_PDU(varbinds_list);
        std::vector<uint8_t> packet_to_send = SNMP_PacketBuilder::make_message(getrequestPDU);
        for (int attempt = 0; attempt <= config.retries; ++attempt) {

            client.SNMP_send(packet_to_send);          // send SNMP GET
            std::vector<uint8_t> received_packet = client.SNMP_receive();  // get answer

        if(!received_packet.empty()) {
           // SNMP_parser parser;
            SNMPResponse parsed_response = parser.parse_response(received_packet);
            if(parsed_response.request_id != current_req_id) {
                std::cerr << "[WARN] Received response for old Request ID "
                          << parsed_response.request_id
                          << ", expected " << SNMP_PacketBuilder::request_id_counter << "\n";
                continue; // ignoruj odpoveď
            }

            exporter.export_gauge(parsed_response);   // export do OTLP
            received = true;
            break;
        } else {
            std::cerr << "[WARN] No response (timeout), retry "
                      << attempt + 1 << "/" << (config.retries + 1) << "\n";
        }

        }
        if (!received) {
            std::cerr << "[ERROR] SNMP agent did not respond after " << config.retries << " retries\n";
            //return 1;
        }

        auto elapsed = std::chrono::steady_clock::now() - start_time;
        auto sleep_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::seconds(config.interval) - elapsed
        );
        if(sleep_ms.count() > 0) {
            std::this_thread::sleep_for(sleep_ms);
        }
    }


    return 0;
}
