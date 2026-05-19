# Makefile for building eBPF programs

CLANG ?= clang
BPF_TARGET := bpf
CFLAGS := -O2 -g -Wall -target $(BPF_TARGET)

SRC := deny_connect.c
OBJ := $(SRC:.c=.o)

all: $(OBJ)

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)
