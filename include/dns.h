/**
 * dns.h - DNS packet structures and parser declarations
 * Part of dns-filter: a DNS-level ad blocking system
 *
 * Based on RFC 1035 (Domain Names - Implementation and Specification)
 */

#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stddef.h>

/* ---------- DNS constants ---------- */
#define DNS_PORT 53
#define DNS_MAX_LABEL_LENGTH 63
#define DNS_MAX_NAME_LENGTH 253

/* ---------- Header flag masks ---------- */
#define DNS_FLAG_QR 0x8000 // Query/Response flag 0 = query, 1 = response
#define DNS_FLAG_OPCODE_MASK 0x7800 // Opcode mask
#define DNS_FLAG_AA 0x0400 // Authoritative Answer
#define DNS_FLAG_TC 0x0200 // Truncated message
#define DNS_FLAG_RD 0x0100 // Recursion Desired
#define DNS_FLAG_RA 0x0080 // Recursion Available
#define DNS_FLAG_Z 0x0070 // Reserved
#define DNS_FLAG_RCODE_MASK 0x000F // Response code mask

/* ---------- Response codes ---------- */
#define DNS_RCODE_NOERROR  0
#define DNS_RCODE_NXDOMAIN 3

/* ---------- Query types ---------- */
#define DNS_QTYPE_A     1		// IPv4 address
#define DNS_QTYPE_AAAA  28		// IPv6 address	  
#define DNS_QTYPE_CNAME 5 		// Canonical name for an alias   

/**
 * DNS header - first 12 bytes of every DNS packet
 * All fields are stored in host byte order after parsing
 */

typedef struct {
	uint16_t id; // matches the query ID in responses
	uint16_t flags; // Flags
	uint16_t qdcount; // Number of questions
	uint16_t ancount; // Number of answers
	uint16_t nscount; // Number of authority records
	uint16_t arcount; // Number of additional records
} dns_header_t;

typedef struct {
	char name[DNS_MAX_NAME_LENGTH + 1]; // Null-terminated domain name
	uint16_t type; // Type of the query
	uint16_t class_; // Class of the query
} dns_question_t;

typedef struct{
	dns_header_t header;
	dns_question_t question; // For simplicity, we handle only one question
	uint8_t raw[512];
	size_t raw_len;
} dns_packet_t;

#endif // DNS_H

