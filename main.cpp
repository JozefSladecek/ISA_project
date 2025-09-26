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

#include <iomanip>

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

#define SNMP_port 161
constexpr int OID_FIRST_BYTE_FACTOR = 40;
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


// uint8_t first_byte;
// uint8_t first_number;
// uint8_t second_number;
//
// for (int i =0; i < all_oids_encoded.size(); ++i) {
//     first_number = all_oids_encoded[i][0];
//     second_number = all_oids_encoded[i][1];
//     uint8_t first_byte = OID_FIRST_BYTE_FACTOR * first_number + second_number;
// }
class SNMP_PacketBuilder {
public:
    static std::vector<std::string> fileLoad(const std::string& filename);
    static std::vector<std::vector<uint32_t>> parse_oids_to_ints(const std::vector<std::string>& oids);
    static std::vector<uint32_t> encode_oids_to_ber(const std::vector<uint32_t>& oid_array);
};


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

std::vector<uint32_t> SNMP_PacketBuilder::encode_oids_to_ber(const std::vector<uint32_t>& oid_array) {
    uint32_t first_byte;
    uint32_t first_number;
    uint32_t second_number;
    std::vector<uint32_t> oid_in_ber;

    first_number = oid_array[0];
    second_number = oid_array[1];
    first_byte = first_number * OID_FIRST_BYTE_FACTOR + second_number;
    oid_in_ber.push_back(first_byte);

    for (int i = 2; i < oid_array.size(); i++) {
        uint32_t value = oid_array[i];
        if (value <= 127) {
            oid_in_ber.push_back(static_cast<uint32_t>(value));
        }
        else {
            std::vector<uint32_t> bytes;
            do {
                uint32_t byte = value & 0x7F; // 7 last bytes because MSB = 0
                bytes.insert(bytes.begin(), byte);
                value >>= 7; // move to save upper 7 bytes
            } while (value > 0);

            for (size_t j = 0; j < bytes.size() - 1; ++j) {
                bytes[j] |= 0x80; // for upper 7 bytes MSB = 1
            }

            oid_in_ber.insert(oid_in_ber.end(), bytes.begin(), bytes.end());

        }
    }

    return oid_in_ber;
}


class SNMP_client {
    public:

    std::string target_ip;
    int socket_fd;
    int port;
    struct sockaddr_in server_addr{};

    // construct
    SNMP_client(const std::string& ip)
        : target_ip(resolveIP(ip)), port(SNMP_port)
    {
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            perror("Error while opening socket");
            socket_fd = -1;
        }
    }

    int SNMP_send(const std::vector<uint8_t>& packet) {
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

        if (sent < 0) { // size of packet
            std::cerr << "Error while sending\n";
            close(socket_fd);
            socket_fd = -1;
            return 1;
        }
        //std::cout << "Packet sent (" << sent << " bytes)\n";
        return 0;
    }

    int SMNP_recieve() {
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(161);

        if (inet_pton(AF_INET, target_ip.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "Invalid IP address\n";
            close(socket_fd);
            socket_fd = -1;
            return 1;
        }

        uint8_t buffer[1024];
        socklen_t addr_len = sizeof(server_addr);

        int received = recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                       (struct sockaddr*)&server_addr, &addr_len);

        if (received < 0) {
            std::cerr << "Error while receiving\n";
            close(socket_fd);
            return 1;
        }

        std::cout << "Received response (" << received << " bytes):\n";
        for (int i = 0; i < received; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << (int)buffer[i] << " ";
            if ((i+1) % 16 == 0) std::cout << "\n";
        }
        std::cout << "\n";
        return 0;

    }


    // deconstruct
    ~SNMP_client() {
        if (socket_fd >= 0) close(socket_fd);
    }

};


int main(int argc, char* argv[]) {

    Config config = parseArgs(argc, argv);


    std::vector<std::string> oids = SNMP_PacketBuilder::fileLoad("oids.txt");


    std::vector<std::vector<uint32_t>> all_oids_int;


    all_oids_int = SNMP_PacketBuilder::parse_oids_to_ints(oids);

    std::vector<std::vector<uint32_t>> all_oids_encoded;

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





    std::string ip = resolveIP(config.target);



    SNMP_client client(ip);

    client.SNMP_send(testpacket);

    client.SMNP_recieve();


    //std::cout << "Resolved IP: " << ip << "\n";

    // for (const auto& oid : oids) {
    //     std::cout << oid << "\n";
    // }

    // std::cout << "Target: " << target << "\n";
    // std::cout << "Community: " << community << "\n";
    // std::cout << "OIDs file: " << oids_file << "\n";
    // std::cout << "OTEL endpoint: " << endpoint << "\n";
    // std::cout << "Interval: " << interval << "s\n";
    // std::cout << "Retries: " << retries << "\n";
    // std::cout << "Timeout: " << timeout << "ms\n";
    // std::cout << "Port: " << port << "\n";
    // std::cout << "Verbose: " << (verbose ? "true" : "false") << "\n";

    return 0;
}

