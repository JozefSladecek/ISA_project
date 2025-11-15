# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -Wextra -g -std=c++17 -I./include

# Target executable
TARGET = snmp2otel

# Source files
SRCS = main.cpp \
       SNMP_PacketBuilder.cpp \
       SNMP_client.cpp \
       SNMP_parser.cpp \
       OTELExporter.cpp

# Object files
OBJS = $(SRCS:.cpp=.o)

# Test executable
TEST_TARGET = unit_tests
TEST_SRCS = tests/unit_tests.cpp \
            SNMP_PacketBuilder.cpp \
            SNMP_parser.cpp \
            OTELExporter.cpp \
            SNMP_client.cpp
TEST_OBJS = $(TEST_SRCS:.cpp=.o)

#==============================================================================
# DEFAULT TARGET
#==============================================================================
all: $(TARGET)

#==============================================================================
# BUILD MAIN EXECUTABLE
#==============================================================================
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Compile source files to object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

#==============================================================================
# RUN TARGET
#==============================================================================
RUN_ARGS = -t 127.0.0.1 -C public -o oids.txt -e http://localhost:4318/v1/metrics -i 10 -v

run: $(TARGET)
	./$(TARGET) $(RUN_ARGS)


#==============================================================================
# TEST TARGETS
#==============================================================================
test: test_unit test_integration

# Unit tests
test_unit: $(TEST_TARGET)
	@echo ""
	@echo "========================================="
	@echo "  Running Unit Tests"
	@echo "========================================="
	@./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SRCS)
	@mkdir -p tests
	$(CXX) $(CXXFLAGS) -o $(TEST_TARGET) $(TEST_SRCS) $(LDFLAGS)

# Integration tests
test_integration: $(TARGET)
	@echo ""
	@echo "========================================="
	@echo "  Running Integration Tests"
	@echo "========================================="
	@chmod +x tests/integration_tests.sh
	@./tests/integration_tests.sh

#==============================================================================
# CLEAN
#==============================================================================
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET) $(TEST_TARGET)
	rm -f $(OBJS)
	rm -f tests/*.o
	rm -f *.o
	@echo "Clean complete."

#==============================================================================
# PHONY TARGETS
#==============================================================================
.PHONY: all run test test_unit test_integration clean