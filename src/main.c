/**
 * main.c - Main entry point for DNS filter application
 * Part of dns-filter: a DNS-level ad blocking system
 * 
 * This file currently is testing dns files
 */

#include <stdio.h>
#include "dns.h"
#include "server.h"

uint8_t test_query[] = {
    /* header */
    0xAA, 0xBB,             /* ID */
    0x01, 0x00,             /* flags: RD=1 */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,             /* ANCOUNT: 0 */
    0x00, 0x00,             /* NSCOUNT: 0 */
    0x00, 0x00,             /* ARCOUNT: 0 */

    /* question: www.google.com A IN */
    0x03, 'w', 'w', 'w',
    0x06, 'g', 'o', 'o', 'g', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,                   /* end of name */
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01              /* QCLASS: IN */
};

// int main() {
//     dns_packet_t pkt;
//     if (dns_parse_packet(test_query, sizeof(test_query), &pkt) == 0) {
//         dns_print_packet(&pkt);
//     } else {
//         fprintf(stderr, "Error parsing DNS packet\n");
//     }
//     return 0;
// }

int main() {
    dns_server_t server;
    if (dns_server_init(&server, 53) == 0) {
        printf("DNS server initialized on port 53\n");
        dns_server_start(&server);
    } else {
        fprintf(stderr, "Failed to initialize DNS server\n");
        return 1;
    }

    dns_server_stop(&server);
    return 0;
}