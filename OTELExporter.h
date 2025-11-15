// Projekt: ISA - snmp2otel
// Autor: Jozef Sládeček
// Login: xsladej00
// Dátum: 17.11.2025

#ifndef ISA_OTELEXPORTER_H
#define ISA_OTELEXPORTER_H
#include <string>
#include "SNMP_parser.h"

struct DataForOTEL {
    std::string name;
    std::string unit;
    std::uint64_t value;
    std::string oid_str;
};



class OTELExporter {
    public:
    explicit OTELExporter(const std::string& target, const std::string& endpoint, bool verbose = false);
    void export_gauge(const SNMPResponse& response);
    std::string oid_to_string(const std::vector<uint32_t>& oid);
    std::string extract_path(const std::string& url);

    struct ParsedURL {
        std::string host;
        int port;
    };

    static ParsedURL parse_host_port(const std::string& url);



    private:
    std::string snmp_target;
    std::string endpoint_host;
    int endpoint_port;
    bool verbose;
    std::string endpoint;
    static bool is_number(const std::string& s);
    std::string build_json(const std::vector<DataForOTEL>& metrics);
    void send_json(std::string json);
    std::vector<DataForOTEL> build_metrics(const SNMPResponse& response);





};


#endif //ISA_OTELEXPORTER_H