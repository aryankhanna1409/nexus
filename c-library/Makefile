CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -g -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -Werror \
           -Wshadow -Wconversion -Wno-sign-conversion -Wstrict-prototypes -fPIC
SAN      = -fsanitize=address,undefined -fno-omit-frame-pointer
BUILD    = build

.PHONY: all test asan clean

all: $(BUILD)/libcallanalyzer.so $(BUILD)/callanalyzer

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/libcallanalyzer.so: src/callanalyzer.c include/callanalyzer.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -shared -o $@ src/callanalyzer.c -lm

$(BUILD)/callanalyzer: src/cli.c src/callanalyzer.c include/callanalyzer.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -o $@ src/cli.c src/callanalyzer.c -lm

$(BUILD)/test: tests/test_callanalyzer.c src/callanalyzer.c include/callanalyzer.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -o $@ tests/test_callanalyzer.c src/callanalyzer.c -lm

$(BUILD)/test-asan: tests/test_callanalyzer.c src/callanalyzer.c include/callanalyzer.h | $(BUILD)
	$(CC) $(CFLAGS) $(SAN) -Iinclude -o $@ tests/test_callanalyzer.c src/callanalyzer.c -lm

test: $(BUILD)/test
	./$(BUILD)/test

# Same tests under AddressSanitizer + UndefinedBehaviorSanitizer (memory bugs fail the run).
asan: $(BUILD)/test-asan
	./$(BUILD)/test-asan

clean:
	rm -rf $(BUILD)
