/**
 * server.c
 * Alessandro Giusti
 * Server implementation for handling client connections and processing requests.
 * 
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "server.h"


int dns_server_init(dns_server_t *server, int port) {

	memset(server, 0, sizeof(dns_server_t));
	server->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (server->sockfd < 0) {
		perror("socket");
		return -1;
	}

	int opt = 1;
	if (setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("setsockopt");
		close(server->sockfd);
		return -1;
	}

	server->bind_addr.sin_family = AF_INET;
	server->bind_addr.sin_port = htons(port);
	server->bind_addr.sin_addr.s_addr = INADDR_ANY;
	server->blocklist = blocklist_init(131072); // Initialize blocklist with 131072 buckets
	blocklist_load_from_file(server->blocklist, "blocklist.txt"); // Load blocklist from file


	if (bind(server->sockfd, (struct sockaddr *)&server->bind_addr, sizeof(server->bind_addr)) < 0) {
		perror("bind");
		close(server->sockfd);
		return -1;
	}

	server->upstream_addr.sin_family = AF_INET;
	server->upstream_addr.sin_port = htons(53); // Default DNS port
	server->upstream_addr.sin_addr.s_addr = inet_addr("8.8.8.8"); // Google DNS

	return 0; // Return 0 on success, -1 on failure
}

int dns_server_start(dns_server_t *server) {
	// Start the server loop to accept and process client requests
	uint8_t buffer[512];
	dns_packet_t pkt;
	struct sockaddr_in client_addr;

	printf("DNS server listening on port %d...\n", ntohs(server->bind_addr.sin_port));
	while (1) {
		socklen_t addr_len = sizeof(client_addr);
		ssize_t n = recvfrom(server->sockfd, buffer, sizeof(buffer), 0,
							(struct sockaddr *)&client_addr, &addr_len);
		
		if (n < 0) {
			perror("recvfrom");
			continue;
		}

		if (dns_parse_packet(buffer, n, &pkt) < 0) {
			fprintf(stderr, "Failed to parse DNS query\n");
			continue;
		}

		dns_print_packet(&pkt);
		
		// Check blocklist
		if (blocklist_contains(server->blocklist, pkt.question.name)) {
			printf("Blocked query for %s\n", pkt.question.name);
			buffer[2] |= 0x80;
			buffer[3] = (buffer[3] & 0xF0) | 3;
			if (sendto(server->sockfd, buffer, n, 0,
						(struct sockaddr *)&client_addr, addr_len) < 0) {
				perror("sendto");
			}
			continue;
		}

		// Forward the query to the upstream DNS server and send the response back to the client
		int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
		
		if (upstream_sock < 0) {
			perror("socket");
			continue;
		}
		struct timeval tv = {2, 0}; // 2 seconds
		setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		if (sendto(upstream_sock, buffer, n, 0, (struct sockaddr *)&server->upstream_addr, sizeof(server->upstream_addr)) < 0) {
			perror("sendto");
			close(upstream_sock);
			continue;
		}

		uint8_t response[512];
		n = recvfrom(upstream_sock, response, sizeof(response), 0, NULL, NULL);
		if (n < 0) {
			perror("recvfrom");
			close(upstream_sock);
			continue;
		}
		if (sendto(server->sockfd, response, n, 0, (struct sockaddr *)&client_addr, addr_len) < 0) {
			perror("sendto");
		}
		close(upstream_sock);


	}

	return 0; // Return 0 on success, -1 on failure
}

void dns_server_stop(dns_server_t *server) {
    if (server->sockfd > 0) {
        close(server->sockfd);
    }
}



