//
// Created by jozef on 10/1/25.
//

#include "OTELExporter.h"

#include <algorithm>

#include "SNMP_parser.h"

#include <ios>
#include <iostream>
#include <ostream>
#include "include/json.hpp"
#include "include/httplib.h"

OTELExporter::OTELExporter(const std::string& host, int port, bool verbose)
    : endpoint_host(host), endpoint_port(port), verbose(verbose) {}


// debug vypis
std::ostream& operator<<(std::ostream& os, const DataForOTEL& d) {
    os << "DataForOTEL { name: " << d.name
       << ", value: " << d.value
       << ", unit: " << d.unit << " }";
    return os;
}

void OTELExporter::export_gauge(const SNMPResponse& response) {
    //std::cout <<  response.request_id << std::endl;
    DataForOTEL data;
    std::vector<DataForOTEL> metrics;
    // todo saving to struct make function for that
    for (const auto& vb : response.varbinds) {
        if (is_number(vb.value)) {
            data.value = std::stoi(vb.value);
            std::string name = "snmp.";
            for (size_t i = 0; i < vb.oid.size(); ++i) {
                name += std::to_string(vb.oid[i]);
                if (i != vb.oid.size() - 1) name += ".";
            }
            data.name = name;
            data.unit = "";
            metrics.push_back(data);
            std::cout << "[DEBUG] " << data << std::endl;
        }
    }

    std::string json = build_json(metrics);

    send_json(json);


    std::cout << json << std::endl;

}

std::string OTELExporter::build_json(const std::vector<DataForOTEL>& metrics) {



    using json = nlohmann::json;

    json j = json::array(); // array of metrics

    for (const auto& m : metrics) {
        json metric;
        metric["name"] = m.name;
        metric["value"] = m.value;
        metric["unit"] = m.unit;
        j.push_back(metric);
    }
    return j.dump(); // string representation
}


void OTELExporter::send_json(std::string json) {

    //https://github.com/yhirose/cpp-httplib


    // HTTP POST
    httplib::Client cli(endpoint_host.c_str(), endpoint_port);
    httplib::Headers headers = { {"Content-Type", "application/json"} };

    auto res = cli.Post("/v1/metrics", headers, json, "application/json");

    if (res) {
        if (verbose) {
            std::cout << "[DEBUG] OTEL POST status: " << res->status << std::endl;
        }
    } else {
        std::cerr << "[ERROR] Failed to send JSON to OTEL endpoint: "
                  << res.error() << std::endl;
    }


}

// todo meanwhile here https://stackoverflow.com/questions/4654636/how-to-determine-if-a-string-is-a-number-with-c
bool OTELExporter::is_number(const std::string& s)
{
    return !s.empty() && std::find_if(s.begin(),
        s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}


//https://github.com/nlohmann/json?tab=readme-ov-file#examples