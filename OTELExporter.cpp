// Projekt: ISA - snmp2otel
// Autor: Jozef Sládeček
// Login: xsladej00
// Dátum: 17.11.2025

#include "OTELExporter.h"

#include <algorithm>

#include "SNMP_parser.h"

#include <ios>
#include <iostream>
#include <ostream>
#include "include/json.hpp"
#include "include/httplib.h"
#include <chrono>
#include <string>

OTELExporter::OTELExporter(const std::string& target, const std::string& endpoint, bool verbose)
    : snmp_target(target), verbose(verbose), endpoint(endpoint)
{
    ParsedURL parsed = parse_host_port(endpoint);
    endpoint_host = parsed.host;
    endpoint_port = parsed.port;

    if (verbose) {
        std::cout << "[DEBUG] OTEL endpoint: " << endpoint_host
                  << ":" << endpoint_port << extract_path(endpoint) << "\n";
    }
}

std::vector<DataForOTEL> OTELExporter::build_metrics(const SNMPResponse& response) {
    std::vector<DataForOTEL> metrics;

    for (const auto& vb : response.varbinds) {
        if (is_number(vb.value)) {
            DataForOTEL data;
            data.value = std::stoi(vb.value);
            data.name = "snmp." + oid_to_string(vb.oid);
            data.unit = "";
            data.oid_str = oid_to_string(vb.oid);
            metrics.push_back(data);
        }
    }

    return metrics;
}

void OTELExporter::export_gauge(const SNMPResponse& response) {
    std::vector<DataForOTEL> metrics = build_metrics(response);

    std::string json = build_json(metrics);

    send_json(json);
}

/// https://github.com/open-telemetry/opentelemetry-proto/blob/v1.8.0/examples/metrics.json
std::string OTELExporter::build_json(const std::vector<DataForOTEL>& metrics) {

    using ordered_json = nlohmann::ordered_json;

    auto now = std::chrono::system_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()).count();

    ordered_json metrics_array = ordered_json::array(); // array of metrics

    for (const auto& m : metrics) {
        ordered_json metric = {
            {"name", m.name},
            {"unit", m.unit},
            {"description", ""},
            {"gauge", {
            {"dataPoints", ordered_json::array({
                {
                    {"asInt", m.value},
                    {"timeUnixNano", std::to_string(nanos)},
                    {"attributes", ordered_json::array({
                        {
                            {"key", "oid"},
                            {"value", {{"stringValue", m.oid_str}}}
                        }
                    })}
                }
            })}
            }}
        };
        metrics_array.push_back(metric);
    }

    ordered_json resource_attrs = ordered_json::array({
        {
            {"key", "service.name"}, // source
            {"value", {{"stringValue", "snmp2otel"}}}
        },
        {
            {"key", "snmp.target"}, // target
            {"value", {{"stringValue", snmp_target}}}
        }
    });


    ordered_json otlp = {
        {"resourceMetrics", ordered_json::array({
            {
                {"resource", {
                    {"attributes", resource_attrs}
                }},
                {"scopeMetrics", ordered_json::array({
                    {
                        {"scope", {
                            {"name", "snmp2otel"},
                            {"version", "1.0.0"}
                        }},
                        {"metrics", metrics_array}
                    }
                })}
            }
        })}
    };

    return otlp.dump(2);

    }


void OTELExporter::send_json(std::string json) {
    std::string path = extract_path(endpoint);

    //https://github.com/yhirose/cpp-httplib
    // HTTP POST
    httplib::Client cli(endpoint_host, endpoint_port);
    httplib::Headers headers = { {"Content-Type", "application/json"} };

    auto res = cli.Post(path, headers, json, "application/json");

    if (res) {
        if (verbose) {
            std::cout << "[DEBUG] OTEL POST status: " << res->status << std::endl;
        }
    } else {
        std::cerr << "[ERROR] Failed to send JSON to OTEL endpoint: "
                  << res.error() << std::endl;
    }
}

// helper functions
// https://stackoverflow.com/questions/4654636/how-to-determine-if-a-string-is-a-number-with-c
bool OTELExporter::is_number(const std::string& s)
{
    return !s.empty() && std::find_if(s.begin(),
        s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

std::string OTELExporter::oid_to_string(const std::vector<uint32_t>& oid) {
    std::string result;
    for (size_t i = 0; i < oid.size(); ++i) {
        if (i > 0) result += ".";
        result += std::to_string(oid[i]);
    }
    return result;
}

std::string OTELExporter::extract_path(const std::string& url) {
    auto pos = url.find("://");
    std::string rest = url;
    if (pos != std::string::npos) {
        rest = url.substr(pos + 3); // skip "http://"
    }

    auto path_pos = rest.find('/');
    if (path_pos != std::string::npos) {
        return rest.substr(path_pos); // path
    }
    return "/"; // else root
}

OTELExporter::ParsedURL OTELExporter::parse_host_port(const std::string& url) {
    ParsedURL result;
    result.port = 4318;  // default port

    std::string rest = url;

    // delete (http:// or https://)
    size_t scheme_pos = rest.find("://");
    if (scheme_pos != std::string::npos) {
        rest = rest.substr(scheme_pos + 3);
    }

    // delete path (all from '/')
    size_t path_pos = rest.find('/');
    if (path_pos != std::string::npos) {
        rest = rest.substr(0, path_pos);
    }

    // "host:port" or "host"
    size_t colon_pos = rest.find(':');
    if (colon_pos != std::string::npos) {
        result.host = rest.substr(0, colon_pos);
        std::string port_str = rest.substr(colon_pos + 1);
        try {
            result.port = std::stoi(port_str);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Invalid port in endpoint URL: " << port_str << "\n";
            result.port = 4318;
        }
    } else {
        result.host = rest;
    }

    return result;
}

//https://github.com/nlohmann/json?tab=readme-ov-file#examples