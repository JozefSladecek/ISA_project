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

#include <iomanip>


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

int fileLoad(const std::string& filename, std::vector<std::string>& oids) {
    std::ifstream infile(filename);

    if (!infile.is_open()) {
        std::cerr << "Error while opening file " << filename << "\n";
        return 1;
    }

    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        oids.push_back(line); // save oids to vector
    }
    return 0;
}

// int connect(std::string &target) {
//     struct addrinfo hints{};
//     struct addrinfo *result;
//
//     hints.ai_family = AF_INET;
//     hints.ai_socktype = SOCK_DGRAM; // flags for getaddrinfo
//
//     int sock = socket(AF_INET, SOCK_DGRAM, 0); // udp ipv4
//
//     if (sock < 0) {
//         std::cerr << "Error while opening socket\n";
//         return 1;
//     }
//     // sockaddr_in server_adress{};
//     // server_adress.sin_family = AF_INET;
//     // server_adress.sin_port = htons(161); // snmp port
//     int status = getaddrinfo(target.c_str(), nullptr, &hints, &result);
//     if (status != 0) {
//         std::cerr << "getaddrinfo error: " << gai_strerror(status) << "\n";
//         exit(1);
//     }
//     std::cout << result;
//
//     struct sockaddr_in ipv4 = *(struct sockaddr_in *)result->ai_addr;
//     freeaddrinfo(result);
//     //inet_pton(AF_INET, "127.0.0.1", &server_adress.sin_addr);
// }

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

// int SNMP_send(const std::string& ip, int& socket_fd) {
//     socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
//
//     struct sockaddr_in server_addr{};
//     server_addr.sin_family = AF_INET;
//     server_addr.sin_port = htons(161);
//
//     if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
//         std::cerr << "Invalid IP address\n";
//         close(socket_fd);
//         socket_fd = -1;
//         return 1;
//     }
//
//     int sent = sendto(socket_fd, testpacket.data(), testpacket.size(), 0,
//                      (struct sockaddr*)&server_addr, sizeof(server_addr));
//
//     if (sent < 0) {
//         std::cerr << "Error while sending\n";
//         close(socket_fd);
//         socket_fd = -1;
//         return 1;
//     }
//
//     std::cout << "Packet sent (" << sent << " bytes)\n";
//     return 0;
// }
//
// int SNMP_receive(int socket_fd, const std::string& ip) {
//     if (socket_fd < 0) {
//         std::cerr << "Invalid socket descriptor\n";
//         return 1;
//     }
//
//     struct sockaddr_in server_addr{};
//     server_addr.sin_family = AF_INET;
//     server_addr.sin_port = htons(161);
//     inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);
//
//     uint8_t buffer[1024];
//     socklen_t addr_len = sizeof(server_addr);
//
//     int received = recvfrom(socket_fd, buffer, sizeof(buffer), 0,
//                            (struct sockaddr*)&server_addr, &addr_len);
//
//     if (received < 0) {
//         std::cerr << "Error while receiving\n";
//         close(socket_fd);
//         return 1;
//     }
//
//     std::cout << "Received response (" << received << " bytes):\n";
//     for (int i = 0; i < received; ++i) {
//         std::cout << std::hex << std::setw(2) << std::setfill('0')
//                   << (int)buffer[i] << " ";
//         if ((i+1) % 16 == 0) std::cout << "\n";
//     }
//     std::cout << "\n";
//
//     close(socket_fd);
//     return 0;
// }


int main(int argc, char* argv[]) {

    Config config = parseArgs(argc, argv);

    std::vector<std::string> oids;

    if (fileLoad(config.oids_file,oids)) {
        return 1;
    }

    std::string ip = resolveIP(config.target);

    SNMP_client client(ip);

    client.SNMP_send(testpacket);

    client.SMNP_recieve();

    //std::cout << "Resolved IP: " << ip << "\n";

    //int socket_fd;

    // if (SNMP_send(ip, socket_fd) != 0) {
    //     return 1; // Chyba pri odosielaní
    // }
    //
    // //  answear
    // if (SNMP_receive(socket_fd, ip) != 0) {
    //     return 1; // Chyba pri prijímaní
    // }


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

