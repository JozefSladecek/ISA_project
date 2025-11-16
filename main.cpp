// Projekt: ISA - snmp2otel
// Autor: Jozef Sládeček
// Login: xsladej00
// Dátum: 17.11.2025
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <cstring>
#include <netdb.h>
#include <chrono>
#include <thread>
#include <signal.h>
#include <stdio.h>

#include "OTELExporter.h"
#include "SNMP_PacketBuilder.h"
#include "SNMP_client.h"
#include "SNMP_parser.h"


volatile sig_atomic_t keep_running = 1;

void signal_handler(int signal) {
    if (signal == SIGINT) {
        keep_running = false;
    }
}


/// args parser
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " -t target [-C community] -o oids_file -e endpoint "
              << "[-i interval] [-r retries] [-T timeout] [-p port] [-v]\n\n"
              << "Required arguments:\n"
              << "  -t target       IP address or DNS name of SNMP agent\n"
              << "  -o oids_file    File with OID list (one per line)\n"
              << "  -e endpoint     OTEL endpoint URL (e.g., http://localhost:4318/v1/metrics)\n\n"
              << "Optional arguments:\n"
              << "  -C community    SNMP v2c community string (default: public)\n"
              << "  -i interval     Polling interval in seconds (default: 10)\n"
              << "  -r retries      Number of retries on timeout (default: 2)\n"
              << "  -T timeout      SNMP query timeout in ms (default: 1000)\n"
              << "  -p port         SNMP agent UDP port (default: 161)\n"
              << "  -v              Verbose mode\n"
              << "  -h              Show this help message\n";
}

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

    while ((opt = getopt(argc, argv, "t:C:o:e:i:r:T:p:vh")) != -1) {
        switch(opt) {
            case 't': config.target = optarg; break;
            case 'C': config.community = optarg; break;
            case 'o': config.oids_file = optarg; break;
            case 'e': config.endpoint = optarg; break;

            case 'i':
                try {
                    config.interval = std::stoi(optarg);
                    if (config.interval <= 0) {
                        std::cerr << "Error: Interval must be > 0\n";
                        exit(1);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid interval value: " << optarg << "\n";
                    exit(1);
                }
                break;

            case 'r':
                try {
                    config.retries = std::stoi(optarg);
                    if (config.retries < 0) {
                        std::cerr << "Error: Retries must be >= 0\n";
                        exit(1);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid retries value: " << optarg << "\n";
                    exit(1);
                }
                break;

            case 'T':
                try {
                    config.timeout = std::stoi(optarg);
                    if (config.timeout <= 0) {
                        std::cerr << "Error: Timeout must be > 0\n";
                        exit(1);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid timeout value: " << optarg << "\n";
                    exit(1);
                }
                break;

            case 'p':
                try {
                    config.port = std::stoi(optarg);
                    if (config.port <= 0 || config.port > 65535) {
                        std::cerr << "Error: Port must be 1-65535\n";
                        exit(1);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid port value: " << optarg << "\n";
                    exit(1);
                }
                break;

            case 'v':
                config.verbose = true;
                break;

            case 'h':
                print_usage(argv[0]);
                exit(0);

            default:
                std::cerr << "Unknown option\n";
                print_usage(argv[0]);
                exit(1);
        }
    }

    // required params
    if (config.target.empty() || config.oids_file.empty() || config.endpoint.empty()) {
        std::cerr << "Error: -t, -o, and -e are required\n\n";
        print_usage(argv[0]);
        exit(1);
    }

    return config;
}
//// args parser



int main(int argc, char* argv[]) {
    // Install a SIGINT (Ctrl+C) handler so the program can exit gracefully.
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = signal_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);
    sigaction(SIGTERM, &sigIntHandler, NULL);

    Config config = parseArgs(argc, argv);

    std::vector<std::string> oids = SNMP_PacketBuilder::fileLoad(config.oids_file);

    if (oids.empty()) {
        std::cerr << "Error: No OIDs loaded from file\n";
        return 1;
    }

    if (config.verbose) {
        std::cout << "[DEBUG] Loaded " << oids.size() << " OID(s)\n";
    }

    std::vector<std::vector<uint32_t>> all_oids_int;
    all_oids_int = SNMP_PacketBuilder::parse_oids_to_ints(oids);

    std::vector<std::vector<uint8_t>> all_oids_encoded;
    for (const auto& oid : all_oids_int) {
        all_oids_encoded.push_back(SNMP_PacketBuilder::encode_oids_to_ber(oid));
    }

    std::vector<std::vector<uint8_t>> varbinds = SNMP_PacketBuilder::make_varbind(all_oids_encoded);
    std::vector<uint8_t> varbinds_list = SNMP_PacketBuilder::make_varbindlist(varbinds);

    if (config.verbose) {
        int oid_index = 1;
        for (const auto& ber_oid : all_oids_int) {
            std::cout << "OID " << oid_index++ << ": ";
            for (size_t i = 0; i < ber_oid.size(); ++i) {
                std::cout << static_cast<int>(ber_oid[i]);
                if (i != ber_oid.size() - 1) {
                    std::cout << ".";
                }
            }
            std::cout << "\n";
        }

    }

    std::string ip = SNMP_client::resolveIP(config.target);
    if (ip.empty()) {
        std::cerr << "Error: Cannot resolve target '" << config.target << "'\n";
        return 1;
    }

    if (config.verbose) {
        std::cout << "[DEBUG] Resolved " << config.target << " -> " << ip << "\n";
    }

    OTELExporter exporter(config.target, config.endpoint, config.verbose);
    std::vector<uint8_t> received_packet;

    SNMP_client client(ip,config.timeout,config.port);

    while (keep_running) {
        SNMP_parser parser;
        bool received = false;
        auto start_time = std::chrono::steady_clock::now();
        uint32_t current_req_id = SNMP_PacketBuilder::request_id_counter;
        std::vector<uint8_t> getrequestPDU = SNMP_PacketBuilder::make_getrequest_PDU(varbinds_list);
        std::vector<uint8_t> packet_to_send = SNMP_PacketBuilder::make_message(getrequestPDU, config.community);
        for (int attempt = 0; attempt <= config.retries; ++attempt) {

            client.SNMP_send(packet_to_send);          // send SNMP GET
            received_packet = client.SNMP_receive();  // get answer

        if(!received_packet.empty()) {
            SNMPResponse parsed_response = parser.parse_response(received_packet);
            if (parsed_response.varbinds.empty()) {
                std::cerr << "[WARN] Failed to parse SNMP response, retry\n";
                continue;
            }
            if(parsed_response.request_id != current_req_id) {
                std::cerr << "[WARN] Received response for old Request ID "
                          << parsed_response.request_id
                          << ", expected " << SNMP_PacketBuilder::request_id_counter << "\n";
                continue; // ignore
            }

            exporter.export_gauge(parsed_response);   // export into OTLP
            received = true;
            break;
        } else {
            std::cerr << "[WARN] No response (timeout), retry "
                      << attempt + 1 << "/" << (config.retries + 1) << "\n";
        }

        }
        if (!received) {
            std::cerr << "[ERROR] SNMP agent did not respond right after " << config.retries << " retries\n";
        }

        auto elapsed = std::chrono::steady_clock::now() - start_time;
        auto interval_duration = std::chrono::seconds(config.interval);
        // ensure each polling cycle respects the configured interval by accounting for processing time and sleeping only the remaining duration

        if (elapsed >= interval_duration) {
            if (config.verbose) {
                auto overtime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    elapsed - interval_duration
                );
                std::cerr << "[WARN] SNMP polling took longer than interval ("
                          << overtime.count() << "ms overtime)\n";
            }
            continue; // skip
        }
        auto sleep_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            interval_duration - elapsed
        );

        if (config.verbose) {
            std::cout << "[DEBUG] Sleeping for " << sleep_duration.count() << "ms\n";
        }

        auto remaining = sleep_duration;
        while (keep_running && remaining.count() > 0) {
            auto step = std::min(remaining, std::chrono::milliseconds(100));
            std::this_thread::sleep_for(step);
            remaining -= step;
        }
    }

    return 0;
}
