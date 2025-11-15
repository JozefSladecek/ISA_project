#!/usr/bin/env python3
"""
Fake SNMP v2c server pre testovanie snmp2otel projektu
Počúva na UDP port 1611 (aby ste nemuseli root)
"""

import socket
import struct
import sys
import time

HOST = '0.0.0.0'
PORT = 1611  # Použijeme 1611 namiesto 161 (netreba root)

# Fake hodnoty pre testovanie
FAKE_VALUES = {
    (1,3,6,1,2,1,1,3,0): (67, 123456),        # sysUpTime - TimeTicks
    (1,3,6,1,2,1,1,5,0): (4, b"test-host"),   # sysName - OCTET STRING
    (1,3,6,1,2,1,1,6,0): (4, b"Test Lab"),    # sysLocation - OCTET STRING
    (1,3,6,1,2,1,1,7,0): (2, 72),             # sysServices - INTEGER
}

def parse_oid_from_ber(data, offset):
    """Parsuje OID z BER encoding"""
    if offset >= len(data) or data[offset] != 0x06:  # OID tag
        return None, offset
    offset += 1

    if offset >= len(data):
        return None, offset
    length = data[offset]
    offset += 1

    start_offset = offset
    end_offset = offset + length

    # Prvý byte obsahuje prvé 2 čísla
    if offset >= len(data):
        return None, offset
    first_byte = data[offset]
    oid = [first_byte // 40, first_byte % 40]
    offset += 1

    # Zvyšok
    while offset < end_offset and offset < len(data):
        value = 0
        while offset < end_offset and offset < len(data):
            byte = data[offset]
            offset += 1
            value = (value << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                break
        oid.append(value)

    return tuple(oid), offset

def encode_oid_to_ber(oid):
    """Enkóduje OID do BER formátu"""
    result = bytearray()
    result.append(oid[0] * 40 + oid[1])

    for num in oid[2:]:
        if num == 0:
            result.append(0)
        else:
            bytes_list = []
            while num > 0:
                bytes_list.insert(0, num & 0x7F)
                num >>= 7
            for i, b in enumerate(bytes_list):
                if i < len(bytes_list) - 1:
                    result.append(b | 0x80)
                else:
                    result.append(b)
    return bytes(result)

def encode_value(asn_type, value):
    """Enkóduje hodnotu do ASN.1 BER"""
    if asn_type == 2:  # INTEGER
        # Simple integer encoding
        if value < 128:
            return bytes([0x02, 0x01, value])
        elif value < 256:
            return bytes([0x02, 0x01, value])
        else:
            # Multi-byte integer
            val_bytes = []
            temp = value
            while temp > 0:
                val_bytes.insert(0, temp & 0xFF)
                temp >>= 8
            return bytes([0x02, len(val_bytes)] + val_bytes)

    elif asn_type == 4:  # OCTET STRING
        return bytes([0x04, len(value)]) + value

    elif asn_type == 67:  # TimeTicks (0x43)
        # Encode as 4-byte big-endian
        val_bytes = struct.pack('>I', value)
        return bytes([0x43, len(val_bytes)]) + val_bytes

    else:
        # NULL
        return bytes([0x05, 0x00])

def build_response(request_data):
    """Zostavi SNMP GetResponse z GetRequest"""
    try:
        offset = 0

        # SEQUENCE
        if request_data[offset] != 0x30:
            print(f"[ERROR] Expected SEQUENCE, got 0x{request_data[offset]:02x}")
            return None
        offset += 1
        msg_len = request_data[offset]
        offset += 1

        # Version (INTEGER)
        if request_data[offset] != 0x02:
            print(f"[ERROR] Expected INTEGER for version")
            return None
        offset += 1
        ver_len = request_data[offset]
        offset += 1
        version = request_data[offset]
        offset += ver_len

        # Community string (OCTET STRING)
        if request_data[offset] != 0x04:
            print(f"[ERROR] Expected OCTET STRING for community")
            return None
        offset += 1
        comm_len = request_data[offset]
        offset += 1
        community = request_data[offset:offset+comm_len]
        offset += comm_len

        print(f"[INFO] Version: {version}, Community: {community.decode()}")

        # PDU (GetRequest = 0xA0)
        if request_data[offset] != 0xA0:
            print(f"[ERROR] Expected GetRequest (0xA0), got 0x{request_data[offset]:02x}")
            return None
        offset += 1
        pdu_len = request_data[offset]
        offset += 1

        # Request ID
        if request_data[offset] != 0x02:
            print(f"[ERROR] Expected INTEGER for request ID")
            return None
        offset += 1
        req_id_len = request_data[offset]
        offset += 1
        request_id = int.from_bytes(request_data[offset:offset+req_id_len], 'big')
        offset += req_id_len

        print(f"[INFO] Request ID: {request_id}")

        # Error status (INTEGER)
        if request_data[offset] != 0x02:
            print(f"[ERROR] Expected INTEGER for error status at offset {offset}")
            return None
        offset += 1
        err_status_len = request_data[offset]
        offset += 1
        offset += err_status_len  # skip value

        # Error index (INTEGER)
        if request_data[offset] != 0x02:
            print(f"[ERROR] Expected INTEGER for error index at offset {offset}")
            return None
        offset += 1
        err_index_len = request_data[offset]
        offset += 1
        offset += err_index_len  # skip value

        # VarBindList
        if request_data[offset] != 0x30:
            print(f"[ERROR] Expected SEQUENCE for varbind list at offset {offset}")
            return None
        offset += 1
        varbind_len = request_data[offset]
        offset += 1

        varbind_list_end = offset + varbind_len

        # Parse OIDs
        oids = []
        while offset < varbind_list_end and offset < len(request_data):
            if request_data[offset] != 0x30:
                print(f"[ERROR] Expected SEQUENCE for varbind at offset {offset}")
                break
            offset += 1
            vb_len = request_data[offset]
            offset += 1

            oid, new_offset = parse_oid_from_ber(request_data, offset)
            if oid:
                oids.append(oid)
                print(f"[INFO] Requested OID: {'.'.join(map(str, oid))}")
                offset = new_offset
                # Skip value (should be NULL for GetRequest)
                if offset < len(request_data):
                    if request_data[offset] == 0x05:  # NULL
                        offset += 1
                        if offset < len(request_data):
                            null_len = request_data[offset]
                            offset += 1 + null_len
            else:
                break

        if not oids:
            print("[ERROR] No OIDs parsed from request")
            return None

        # Build response
        response = bytearray()

        # Build varbinds with values
        varbinds = bytearray()
        for oid in oids:
            varbind = bytearray()

            # OID
            oid_ber = encode_oid_to_ber(oid)
            varbind.append(0x06)
            varbind.append(len(oid_ber))
            varbind.extend(oid_ber)

            # Value
            if oid in FAKE_VALUES:
                asn_type, value = FAKE_VALUES[oid]
                value_ber = encode_value(asn_type, value)
                varbind.extend(value_ber)
                print(f"[DEBUG] Responding with value: {value}")
            else:
                # NULL (OID not found)
                varbind.extend([0x05, 0x00])
                print(f"[WARNING] OID not in fake database")

            # Wrap in SEQUENCE
            vb_seq = bytearray([0x30, len(varbind)])
            vb_seq.extend(varbind)
            varbinds.extend(vb_seq)

        # VarBindList SEQUENCE
        varbind_list = bytearray([0x30, len(varbinds)])
        varbind_list.extend(varbinds)

        # PDU (GetResponse = 0xA2)
        pdu = bytearray()
        pdu.extend([0x02, req_id_len])
        pdu.extend(request_id.to_bytes(req_id_len, 'big'))
        pdu.extend([0x02, 0x01, 0x00])  # Error status = 0
        pdu.extend([0x02, 0x01, 0x00])  # Error index = 0
        pdu.extend(varbind_list)

        pdu_packet = bytearray([0xA2, len(pdu)])
        pdu_packet.extend(pdu)

        # Message
        message = bytearray()
        message.extend([0x02, 0x01, version])
        message.extend([0x04, len(community)])
        message.extend(community)
        message.extend(pdu_packet)

        response = bytearray([0x30, len(message)])
        response.extend(message)

        return bytes(response)

    except Exception as e:
        print(f"[ERROR] Failed to build response: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))

    print(f"🚀 Fake SNMP server listening on {HOST}:{PORT}")
    print(f"📋 Use this in your client: -t localhost -p {PORT}")
    print(f"🔑 Community: public")
    print(f"📊 Available OIDs:")
    for oid in FAKE_VALUES.keys():
        print(f"   - {'.'.join(map(str, oid))}")
    print(f"\n🛑 Press Ctrl+C to stop\n")

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            print(f"\n=== Received request from {addr} ===")
            print(f"Raw ({len(data)} bytes): {data.hex()}")

            response = build_response(data)
            if response:
                sock.sendto(response, addr)
                print(f"[INFO] Sent response ({len(response)} bytes)")
                print(f"Raw response: {response.hex()}")
            else:
                print("[ERROR] Failed to build response")

            print("=" * 50)

    except KeyboardInterrupt:
        print("\n\n🛑 Stopping server...")
        sock.close()
        sys.exit(0)

if __name__ == '__main__':
    main()