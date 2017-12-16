
CC = gcc
INCLUDE := -I../include/
LDFLAGS := -pthread
CFLAGS := -g -Wall $(INCLUDE)

PROGNAME = hub pipe mgdump ppktgen hwtstampcfg

all: $(PROGNAME)

.c.o:
	$(CC) $< -o $@

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
