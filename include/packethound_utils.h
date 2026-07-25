#ifndef PHND_UTILS_H
#define PHND_UTILS_H



#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/types.h>

typedef enum {
    TABLE_ETH = 0,
    TABLE_IP = 1,
    TABLE_ARP = 2,
    TABLE_ICMP = 3,
} Table_id;

typedef struct {
    int prot_code;
    const char* translation;
} code_name_pair;

struct iterator{
    size_t bytes_remaining;
    const uint8_t* rd_ptr;
};

typedef enum {
    PARSE_PACKET_SUCCESS,
    PARSE_PACKET_FAILURE
} parse_packet_result;

typedef enum {
    PACKET_CATEGORY_UDP_OVER_IP,
    PACKET_CATEGORY_TCP_OVER_IP,
    PACKET_CATEGORY_ARP,
    PACKET_CATEGORY_ICMP,
    PACKET_CATEGORY_NOT_HANDLED

}packet_category;



parse_packet_result parse_packet(const uint8_t *data, size_t bytes, packet_category* categ);
parse_packet_result parse_ethernet(struct iterator* iter, uint16_t* eth_proto);
parse_packet_result parse_tcp(struct iterator* iter);
parse_packet_result parse_udp(struct iterator* iter);
parse_packet_result parse_arp(struct iterator* iter);
parse_packet_result parse_ip(struct iterator* iter, uint8_t* ip_proto);
parse_packet_result parse_icmp(struct iterator* iter);

// liberally "burrowed" from /linux/if_arp.h and defined here for convenience.
struct arppld {
    unsigned char ar_sha[ETH_ALEN]; /* sender hardware address	*/
    unsigned char ar_sip[4];        /* sender IP address		*/
    unsigned char ar_tha[ETH_ALEN]; /* target hardware address	*/
    unsigned char ar_tip[4];        /* target IP address		*/
};

#endif
