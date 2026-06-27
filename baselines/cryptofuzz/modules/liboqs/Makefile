BUILD_DIR ?= .
BUILD_DIR := $(abspath $(BUILD_DIR))

all: $(BUILD_DIR)/module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I $(REPOSITORY_INCLUDE_PATH) -I ../../include -I ../../fuzzing-headers/include -I ../.. -DFUZZING_HEADERS_NO_IMPL -DCRYPTOFUZZ_LIBOQS

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/module.a: $(BUILD_DIR)/module.o
	rm -f $@
	ar rcs $@ $<
	ranlib $@

$(BUILD_DIR)/module.o: module.cpp module.h | $(BUILD_DIR)
	test $(OQS_INCLUDE_PATH)
	test $(REPOSITORY_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(OQS_INCLUDE_PATH) -fPIC -c module.cpp -o $@

clean:
	rm -rf $(BUILD_DIR)/module.o $(BUILD_DIR)/module.a
