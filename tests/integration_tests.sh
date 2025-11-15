#!/bin/bash
# Projekt: ISA - snmp2otel
# Autor: Jozef Sládeček
# Login: xsladej00
# Integration tests

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "========================================="
echo "  ISA snmp2otel - Integration Tests"
echo "========================================="
echo ""

TESTS_PASSED=0
TESTS_TOTAL=0

# Test helper function
run_test() {
    local test_name="$1"
    echo -n "Running $test_name... "
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

pass_test() {
    echo "PASSED"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
    echo "FAILED"
    echo "  Error: $1"
}

#=============================================================================
# TEST 1: Build test
#=============================================================================
run_test "build_test"

cd "$PROJECT_DIR"
if make clean > /dev/null 2>&1 && make > /dev/null 2>&1; then
    if [ -f "./snmp2otel" ]; then
        pass_test
    else
        fail_test "Executable not created"
    fi
else
    fail_test "Build failed"
fi

#=============================================================================
# TEST 2: Help test
#=============================================================================
run_test "help_test"

if ./snmp2otel -h > /dev/null 2>&1; then
    pass_test
else
    fail_test "Help flag failed"
fi

#=============================================================================
# TEST 3: Missing arguments test
#=============================================================================
run_test "missing_args_test"

if ./snmp2otel > /dev/null 2>&1; then
    fail_test "Should fail without arguments"
else
    pass_test
fi

#=============================================================================
# TEST 4: Invalid OID file test
#=============================================================================
run_test "invalid_file_test"

if ./snmp2otel -t localhost -o /nonexistent/file.txt -e http://localhost:4318/v1/metrics > /dev/null 2>&1; then
    fail_test "Should fail with non-existent file"
else
    pass_test
fi

#=============================================================================
# TEST 5: Invalid port test
#=============================================================================
run_test "invalid_port_test"

if ./snmp2otel -t localhost -p 99999 -o oids.txt -e http://localhost:4318/v1/metrics > /dev/null 2>&1; then
    fail_test "Should fail with invalid port"
else
    pass_test
fi

#=============================================================================
# Summary
#=============================================================================
echo ""
echo "========================================="
echo "Results: $TESTS_PASSED/$TESTS_TOTAL tests passed"
echo "========================================="

if [ $TESTS_PASSED -eq $TESTS_TOTAL ]; then
    exit 0
else
    exit 1
fi