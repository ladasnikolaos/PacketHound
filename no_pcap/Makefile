CC := gcc
CSTD := gnu99
CFLAGS := -std=$(CSTD) -Wall -Wextra -g -Iinclude

SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,build/%.o,$(SRC))
TARGET := target/main

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJ) | target
	$(CC) $(OBJ) -o $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

target:
	mkdir -p target

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	$(RM) -r build target
