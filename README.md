# Exportér SNMP Gauge metrik do OpenTelemetry (OTEL)

**Autor:** Jozef Sládeček  
**Login:** xsladej00  
**Dátum:** 17.11.2025  

## Popis programu
`snmp2otel` je nástroj, ktorý pravidelne dotazuje SNMP agenta (verzia v2c) na zadané OID a exportuje získané hodnoty ako OpenTelemetry (OTEL) Metrics vo formáte JSON cez OTLP/HTTP. Program spracováva metriky typu Gauge a podporuje nastavenie intervalu, retry, timeoutu a SNMP community stringu.

## Známe obmedzenia:
Podľa zadania projektu sú nasledovné obmedzenia:
- Podpora voliteľného mapping souboru (názov, unit, typ) zatiaľ nie je implementovaná.
- Program podporuje iba metriky typu Gauge.
- Dotazovanie funguje len pre skalárne OID končiace `.0`.
- Podporovaná je len SNMP verzia v2c.

## Použitie
**Argumenty:**
- `-t target` — IP adresa alebo DNS jméno SNMP agenta.
- `-C community` — SNMP v2c community string (default: public).
- `-o oids_file` — súbor so zoznamom OID, ktoré sa majú dotazovať.
- `-e endpoint` — URL OTEL endpointu pre export (OTLP/HTTP JSON), napr. http://localhost:4318/v1/metrics.
- `-i interval` — perioda dotazovania v sekundách (>0). Default: 10.
- `-r retries` — počet retransmisí pri timeoutu SNMP dotazu. Default: 2.
- `-T timeout` — timeout SNMP dotazu v ms. Default: 1000.
- `-p port` — UDP port SNMP agenta. Default: 161.
- `-v` — verbose režim.

## Príklad spustenia
`./snmp2otel -t 127.0.0.1 -C public -o oids.txt -e http://localhost:4318/v1/metrics -i 10 -v`

## Odevzdané súbory
- `main.cpp` — hlavný program
- `SNMP_client.h/cpp` — SNMP klient UDP
- `SNMP_PacketBuilder.h/cpp` — tvorba SNMP paketov
- `SNMP_parser.h/cpp` — parsovanie SNMP odpovedí
- `OTELExporter.h/cpp` — export do OTEL
- `Makefile` — build a testovanie projektu
- `oids.txt` — txt súbor so zoznamom OID
- `include/` — hlavičkové súbory projektu
- `tests/` — testy (unit, integračné)
