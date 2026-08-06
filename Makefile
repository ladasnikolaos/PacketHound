CC := gcc
CSTD := gnu17
CFLAGS := -std=$(CSTD) -Wall -Wextra -Wpedantic -Werror -g -Iinclude -MMD -MP

SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,build/%.o,$(SRC))
-include $(OBJ:.o=.d)
TARGET := target/phound

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
