/**
 * cache.h - Header file for DNS cache implementation.
 * The DNS cache is used to store recently resolved DNS queries and their responses to improve performance and reduce latency for frequently accessed domains. The cache is implemented as a simple hash table with a fixed size, and it supports basic operations such as adding entries, retrieving entries, and clearing expired entries.
 * The cache entries include the domain name, the corresponding IP address, and a timestamp to track when the entry was added. The cache is designed to be thread-safe for concurrent access in a multi-threaded server environment.
 * 
 */
#ifndef CACHE_H
#define CACHE_H

#include <time.h>
#include "dns.h"

typedef struct cache_entry {
	char *domain;           // The domain name (e.g., "example.com")
	uint8_t response[512];    // The raw DNS response data (up to 512 bytes)
	size_t response_len;     // Length of the DNS response data
	time_t expires_at;       // Timestamp of when the entry expires
	struct cache_entry *next; // Pointer to the next entry in the bucket (for handling collisions)
} cache_entry_t;

typedef struct {
	size_t size;           // Size of the hash table (number of buckets)
	cache_entry_t **buckets; // Array of pointers to cache entries (hash table)
} dns_cache_t;

dns_cache_t *cache_init(size_t size);
void cache_free(dns_cache_t *cache);
int cache_add(dns_cache_t *cache, const char *domain, const uint8_t *response, size_t response_len, time_t ttl);
int cache_get(dns_cache_t *cache, const char *domain, uint8_t *response, size_t *response_len);
void cache_clear_expired(dns_cache_t *cache);

#endif /* CACHE_H */