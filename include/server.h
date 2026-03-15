/**
 * @file server.h
 * @author your name (Alessandro Giusti)
 * @brief Server implementation for handling client connections and processing requests.
 * @version 0.1
 * @date 2024-06-01
 * 
 */
#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>
#include "dns.h"
#include "blocklist.h"


typedef struct {
	int sockfd;
	struct sockaddr_in bind_addr;
	struct sockaddr_in upstream_addr;
	blocklist_t *blocklist; // Pointer to the blocklist for filtering queries
} dns_server_t;

int dns_server_init(dns_server_t *server, int port);
int dns_server_start(dns_server_t *server);
void dns_server_stop(dns_server_t *server);



#endif /* SERVER_H */