/**
 * blocklist.h - Blocklist management for the application.
 * This header defines the interface for managing a blocklist of domains or IP addresses.
 * The blocklist can be used to filter out unwanted traffic or block access to certain resources.	
 * 
 * list stored in hash table for efficient lookup. The blocklist can be loaded from a file or managed in memory.
 *
 */

#ifndef BLOCKLIST_H
#define BLOCKLIST_H

#include <stdint.h>

// Define the blocklist entry structure
typedef struct blocklist_entry {
	char *domain; // Domain name to block
	struct blocklist_entry *next; // Pointer to the next entry in the hash bucket
} blocklist_entry_t;

// Define the blocklist structure
typedef struct {
	blocklist_entry_t **buckets; // Hash table buckets
	size_t size; // Size of the hash table
} blocklist_t;

// Function prototypes
blocklist_t *blocklist_init(size_t size);
void blocklist_free(blocklist_t *blocklist);
int blocklist_add(blocklist_t *blocklist, const char *domain);
int blocklist_remove(blocklist_t *blocklist, const char *domain);
int blocklist_contains(blocklist_t *blocklist, const char *domain);

void blocklist_load_from_file(blocklist_t *blocklist, const char *filename);

#endif /* BLOCKLIST_H */
