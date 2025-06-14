CC=gcc
LD=ld
CFLAGS=-Wall -Wextra -Werror -O2

SSLFLAGS= -lssl -lcrypto
CFILES:=$(shell ls *.c 2>/dev/null)
HFILES:=$(shell ls *.h 2>/dev/null)
COBJS:=$(CFILES:%.c=%.o)
TARGET=socat-plus

all: $(TARGET)

$(TARGET): $(COBJS) 
	$(CC) $(COBJS) -o $@ $(SSLFLAGS)

$(COBJS): $(HFILES)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $<

.PRECIOUS: $(TARGET)
.PHONY: clean

clean:
	rm -f $(TARGET) *.o
