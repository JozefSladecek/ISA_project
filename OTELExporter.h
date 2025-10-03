//
// Created by jozef on 10/1/25.
//

#ifndef ISA_OTELEXPORTER_H
#define ISA_OTELEXPORTER_H
#include <string>
#include "SNMP_parser.h"

struct DataForOTEL {
    std::string name;
    std::string unit;
    std::uint64_t value;
};



class OTELExporter {
    public:
    explicit OTELExporter(const std::string& host, int port, bool verbose = false);
    void export_gauge(const SNMPResponse& response);


    private:
    std::string endpoint_host;
    int endpoint_port;
    bool verbose;
    static bool is_number(const std::string& s);
    std::string build_json(const std::vector<DataForOTEL>& metrics);
    void send_json(std::string json);


};


#endif //ISA_OTELEXPORTER_H