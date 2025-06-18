CC=gcc
LD=ld
OUTDIR=build

CFLAGS=-Wall -Wextra -Werror -O2
LDFLAGS= -lssl -lcrypto

CFILES:=$(shell ls src/*.c 2>/dev/null)
HFILES:=$(shell ls src/*.h 2>/dev/null)
COBJS:=$(patsubst src/%.c, $(OUTDIR)/%.o, $(CFILES))

TARGET=socat-plus

all: $(TARGET)

$(TARGET): $(COBJS) 
	$(CC) $(COBJS) -o $@ $(LDFLAGS)

$(COBJS): $(HFILES)

$(OUTDIR)/%.o: %.c | $(OUTDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTDIR):
	mkdir -p $(OUTDIR)

.PRECIOUS: $(TARGET)
.PHONY: clean

clean:
	rm -f $(TARGET) *.o
