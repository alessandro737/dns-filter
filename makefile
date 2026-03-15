CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
SRC = src/main.c src/dns.c src/server.c src/blocklist.c src/cache.c
OUT = dns-filter

all:
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)

clean:
	rm -f $(OUT)
