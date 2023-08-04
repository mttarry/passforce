# Makefile for passforce project

# Compiler and flags
CC := gcc
CFLAGS := 
LDFLAGS := -lssl -lcrypto

# Directories
SRCDIR := src
INCDIR := include

# Source files and output executable
SRC := $(wildcard $(SRCDIR)/*.c)
INCLUDE := -I$(INCDIR)
EXEC := passforce

all: $(EXEC)

$(EXEC): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDE) $^ $(LDFLAGS) -o $@

debug: CFLAGS += -DDEBUG
debug: $(EXEC)

clean:
	rm -f $(EXEC)

.PHONY: all debug clean