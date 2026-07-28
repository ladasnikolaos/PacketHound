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

// liberally "burrowed" from /linux/if_arp.h and defined here for convenience.
struct arppld {
    unsigned char ar_sha[ETH_ALEN]; /* sender hardware address	*/
    unsigned char ar_sip[4];        /* sender IP address		*/
    unsigned char ar_tha[ETH_ALEN]; /* target hardware address	*/
    unsigned char ar_tip[4];        /* target IP address		*/
};

#endif
