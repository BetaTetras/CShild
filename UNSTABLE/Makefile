# Makefile CShild (UNSTABLE) : CLI avec CSON + AES-256-GCM
# Utilisation : make | make run | make clean

CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -O2 -Iinclude/CSON -Iinclude/AES-256-GCM -Iinclude/common
LDLIBS  =

# Sous Windows (MSYS2), AES.c a besoin de bcrypt pour BCryptGenRandom
ifeq ($(OS),Windows_NT)
    LDLIBS += -lbcrypt
    EXE     = .exe
endif

BUILD = build
CLI   = cshild$(EXE)

LIB_OBJ = $(BUILD)/cson.o $(BUILD)/AES.o $(BUILD)/bt_utils.o $(BUILD)/bt_log.o $(BUILD)/bt_api.o $(BUILD)/bt_printf.o
CLI_OBJ = $(BUILD)/cli.o

all: $(CLI)

$(CLI): $(CLI_OBJ) $(LIB_OBJ)
	$(CC) $^ -o $@ $(LDLIBS)

$(BUILD)/cli.o: src/CLI/cli.c include/CSON/cson.h include/AES-256-GCM/AES.h include/common/bt_utils.h include/common/bt_printf.h include/common/bt_api.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cson.o: include/CSON/cson.c include/CSON/cson.h include/common/bt_utils.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/AES.o: include/AES-256-GCM/AES.c include/AES-256-GCM/AES.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/bt_utils.o: include/common/bt_utils.c include/common/bt_utils.h include/common/bt_log.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/bt_log.o: include/common/bt_log.c include/common/bt_log.h include/common/bt_utils.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/bt_api.o: include/common/bt_api.c include/common/bt_api.h include/common/bt_utils.h include/common/bt_log.h include/CSON/cson.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/bt_printf.o: include/common/bt_printf.c include/common/bt_printf.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD):
	mkdir -p $(BUILD)

run: $(CLI)
	./$(CLI)

clean:
	rm -rf $(BUILD) $(CLI)

.PHONY: all run clean
