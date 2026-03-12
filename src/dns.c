#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns.h"

#define DNS_HEADER_SIZE 12
#define DNS_PACKET_SIZE 512

/**
 * dns_parse_header - Parse the 12-byte DNS header from raw bytes
 * @param buf pointer to raw packet data
 * @param len length of the buffer
 * @param hdr pointer to header struct to fill
 * @return 0 on success, -1 on error
 */
int dns_parse_header(const uint8_t *buf, size_t len, dns_header_t *hdr)
{
    if (len < DNS_HEADER_SIZE) {
		return -1; // Not enough data for header
	}

	// DNS header fields are in network byte order, convert to host byte order
	hdr->id = ntohs(*(uint16_t *)(buf));
	hdr->flags = ntohs(*(uint16_t *)(buf + 2));
	hdr->qdcount = ntohs(*(uint16_t *)(buf + 4));
	hdr->ancount = ntohs(*(uint16_t *)(buf + 6));
	hdr->nscount = ntohs(*(uint16_t *)(buf + 8));
	hdr->arcount = ntohs(*(uint16_t *)(buf + 10));

	return 0; // Success
}

/**
 * dns_decode_name - Decode a DNS-encoded domain name
 * @param buf    pointer to the FULL packet (needed for compression pointers later)
 * @param len    total length of the packet
 * @param offset where the name starts in the buffer
 * @param out    output buffer for the decoded string
 * @param out_size size of the output buffer
 * @return number of bytes consumed from buf, or -1 on error
 */
int dns_decode_name(const uint8_t *buf, size_t len, size_t offset,
                    char *out, size_t out_size)
{
	size_t out_pos = 0;
	size_t pos = offset;
	while (pos < len) {
		uint8_t label_len = buf[pos];
		if (label_len == 0) {
			// End of name
			if (out_pos < out_size) {
				out[out_pos] = '\0'; // Null-terminate
			}
			return pos - offset + 1; // Total bytes consumed
		}

		if (label_len & 0xC0) {
			// Compression pointer (not handled in this simple implementation)
			return -1; // Compression not supported in this basic parser
		}

		pos++; // Move past length byte

		if (pos + label_len > len || out_pos + label_len + 1 > out_size) {
			return -1; // Not enough data or output buffer too small
		}

		if (out_pos > 0) {
			out[out_pos++] = '.'; // Add dot between labels
		}

		memcpy(out + out_pos, buf + pos, label_len);
		out_pos += label_len;
		pos += label_len;
	}
	return -1; // Name not properly terminated
}

/**
 * dns_parse_packet - Parse a complete DNS packet
 * @param buf pointer to raw packet data
 * @param len length of the buffer
 * @param pkt pointer to packet struct to fill
 * @return 0 on success, -1 on error
 */
int dns_parse_packet(const uint8_t *buf, size_t len, dns_packet_t *pkt)
{
	memset(pkt, 0, sizeof(dns_packet_t)); // Clear the packet struct

	// copy raw bytes into pkt->raw
	pkt->raw_len = len < DNS_PACKET_SIZE ? len : DNS_PACKET_SIZE;
	memcpy(pkt->raw, buf, pkt->raw_len);

	if (dns_parse_header(buf, len, &pkt->header) < 0) {
		return -1; // Error parsing header
	}

	if (pkt->header.qdcount > 0) {
		int name = dns_decode_name(buf, len, DNS_HEADER_SIZE, pkt->question.name, sizeof(pkt->question.name));
		if (name < 0) {
			return -1; // Error decoding name
		}

		size_t offset = DNS_HEADER_SIZE + name;
		if (offset + 4 > len) {
			return -1; // Not enough data for QTYPE and QCLASS
		}
		pkt->question.type = ntohs(*(uint16_t *)(buf + offset));
		pkt->question.class_ = ntohs(*(uint16_t *)(buf + offset + 2));
	}

	return 0; // Success
}

void dns_print_packet(const dns_packet_t *pkt)
{
	printf("DNS Packet:\n");
	printf("ID: 0x%04X\n", pkt->header.id);
	printf("Type: %s\n", (pkt->header.flags & DNS_FLAG_QR) ? "RESPONSE" : "QUERY");
	printf("Flags: 0x%04X\n", pkt->header.flags);
	printf("Questions: %u\n", pkt->header.qdcount);
	printf("Answers: %u\n", pkt->header.ancount);
	printf("Authority RRs: %u\n", pkt->header.nscount);
	printf("Additional RRs: %u\n", pkt->header.arcount);

	if (pkt->header.qdcount > 0) {
		printf("Question:\n");
		printf("  Name: %s\n", pkt->question.name);
		printf("  Type: %u\n", pkt->question.type);
		printf("  Class: %u\n", pkt->question.class_);
	}
}