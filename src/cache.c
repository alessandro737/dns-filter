/**
 * cache.c - Implementation of the DNS cache for storing recently resolved queries and their responses.
 * The DNS cache is designed to improve performance by storing the results of recent DNS queries, allowing
 * the server to quickly respond to repeated queries without needing to forward them to the upstream DNS server. The cache is implemented as a simple hash table with a fixed size, and it supports adding new entries, retrieving existing entries, and clearing expired entries based on their TTL (Time To Live). Each cache entry includes the domain name, the corresponding DNS response, and an expiration timestamp to ensure that stale entries are removed from the cache. The cache is also designed to be thread-safe for use in a multi-threaded server environment.
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cache.h"

static size_t hash_domain(const char *domain, size_t size) {
	size_t hash = 0;
	for (const char *p = domain; *p; p++) {
		hash = (hash * 31 + *p) % size;
	}
	return hash;
}

dns_cache_t *cache_init(size_t size) {
	dns_cache_t *cache = malloc(sizeof(dns_cache_t));
	if (!cache) {
		return NULL;
	}
	cache->size = size;
	cache->buckets = calloc(size, sizeof(cache_entry_t *));
	if (!cache->buckets) {
		free(cache);
		return NULL;
	}
	return cache;
}

void cache_free(dns_cache_t *cache) {
	if (!cache) {
		return;
	}
	for (size_t i = 0; i < cache->size; i++) {
		cache_entry_t *entry = cache->buckets[i];
		while (entry) {
			cache_entry_t *temp = entry;
			entry = entry->next;
			free(temp->domain);
			free(temp);
		}
	}
	free(cache->buckets);
	free(cache);
}

int cache_add(dns_cache_t *cache, const char *domain, const uint8_t *response, size_t response_len, time_t ttl) {
	if (!cache || !domain || !response || response_len == 0) {
		return -1;
	}
	size_t hash = hash_domain(domain, cache->size);
	cache_entry_t *new_entry = malloc(sizeof(cache_entry_t));
	if (!new_entry) {
		return -1;
	}
	new_entry->domain = strdup(domain);
	memcpy(new_entry->response, response, response_len);
	new_entry->response_len = response_len;
	new_entry->expires_at = time(NULL) + ttl; // Set TTL for the cache entry
	new_entry->next = cache->buckets[hash];
	cache->buckets[hash] = new_entry;
	return 0;
}

int cache_get(dns_cache_t *cache, const char *domain, uint8_t *response, size_t *response_len) {
	if (!cache || !domain || !response || !response_len) {
		return -1;
	}
	size_t hash = hash_domain(domain, cache->size);
	cache_entry_t *entry = cache->buckets[hash];
	while (entry) {
		if (strcmp(entry->domain, domain) == 0) {
			if (time(NULL) < entry->expires_at) {
				memcpy(response, entry->response, entry->response_len);
				*response_len = entry->response_len;
				return 0; // Cache hit
			} else {
				return -1; // Cache expired
			}
		}
		entry = entry->next;
	}
	return -1; // Cache miss
}

void cache_clear_expired(dns_cache_t *cache) {
	if (!cache) {
		return;
	}
	time_t now = time(NULL);
	for (size_t i = 0; i < cache->size; i++) {
		cache_entry_t *entry = cache->buckets[i];
		cache_entry_t *prev = NULL;
		while (entry) {
			if (now >= entry->expires_at) {
				if (prev) {
					prev->next = entry->next;
				} else {
					cache->buckets[i] = entry->next;
				}
				cache_entry_t *temp = entry;
				entry = entry->next;
				free(temp->domain);
				free(temp);
			} else {
				prev = entry;
				entry = entry->next;
			}
		}
	}
}

