/**
 * blocklist.h - Blocklist management for the application.
 * This header defines the interface for managing a blocklist of domains or IP addresses.
 * The blocklist can be used to filter out unwanted traffic or block access to certain resources.
 * The blocklist is stored in a hash table for efficient lookup. The blocklist can be loaded from a file or managed in memory.
 * 
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "blocklist.h"

static size_t hash_domain(const char *domain, size_t size) {
    size_t hash = 0;
    for (const char *p = domain; *p; p++) {
        hash = (hash * 31 + *p) % size;
    }
    return hash;
}

blocklist_t *blocklist_init(size_t size) {
	blocklist_t *blocklist = malloc(sizeof(blocklist_t));
	if (!blocklist) {
		return NULL;
	}
	blocklist->size = size;
	blocklist->buckets = calloc(size, sizeof(blocklist_entry_t *));
	if (!blocklist->buckets) {
		free(blocklist);
		return NULL;
	}
	return blocklist;
}

void blocklist_free(blocklist_t *blocklist) {
	if (!blocklist) {
		return;
	}
	for (size_t i = 0; i < blocklist->size; i++) {
		blocklist_entry_t *entry = blocklist->buckets[i];
		while (entry) {
			blocklist_entry_t *temp = entry;
			entry = entry->next;
			free(temp->domain);
			free(temp);
		}
	}
	free(blocklist->buckets);
	free(blocklist);
}

int blocklist_add(blocklist_t *blocklist, const char *domain) {
	if (!blocklist || !domain) {
		return -1;
	}
	size_t hash = hash_domain(domain, blocklist->size);
	blocklist_entry_t *new_entry = malloc(sizeof(blocklist_entry_t));
	if (!new_entry) {
		return -1;
	}
	new_entry->domain = strdup(domain);
	new_entry->next = blocklist->buckets[hash];
	blocklist->buckets[hash] = new_entry;
	return 0;
}

int blocklist_contains(blocklist_t *blocklist, const char *domain) {
	if (!blocklist || !domain) {
		return 0;
	}
	size_t hash = hash_domain(domain, blocklist->size);
	blocklist_entry_t *entry = blocklist->buckets[hash];
	while (entry) {
		if (strcmp(entry->domain, domain) == 0) {
			return 1; // Domain is in the blocklist
		}
		entry = entry->next;
	}
	return 0; // Domain is not in the blocklist
}

int blocklist_remove(blocklist_t *blocklist, const char *domain) {
	if (!blocklist || !domain) {
		return -1;
	}
	size_t hash = hash_domain(domain, blocklist->size);
	blocklist_entry_t *entry = blocklist->buckets[hash];
	blocklist_entry_t *prev = NULL;
	while (entry) {
		if (strcmp(entry->domain, domain) == 0) {
			if (prev) {
				prev->next = entry->next;
			} else {
				blocklist->buckets[hash] = entry->next;
			}
			free(entry->domain);
			free(entry);
			return 0; // Successfully removed
		}
		prev = entry;
		entry = entry->next;
	}
	return -1; // Domain not found
}

void blocklist_load_from_file(blocklist_t *blocklist, const char *filename) {
	FILE *file = fopen(filename, "r");
	if (!file) {
		perror("fopen");
		return;
	}

	char line[256];
	while (fgets(line, sizeof(line), file)) {
		// Remove newline character
		line[strcspn(line, "\r\n")] = 0;
		if (strlen(line) > 0) {
			blocklist_add(blocklist, line);
		}
	}
	fclose(file);
}

