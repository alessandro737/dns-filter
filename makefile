CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
SRC = src/main.c src/dns.c src/server.c
OUT = dns-filter

all:
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)

clean:
	rm -f $(OUT)
