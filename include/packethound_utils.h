#ifndef PHND_UTILS_H
#define PHND_UTILS_H

#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17
#define PROTOCOL_ICMP 1

#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

typedef enum {
    ETH = 0,
    IP = 1,
    ARP = 2,
    ICMP = 3,
} Table_id;

typedef struct {
    int prot_code;
    const char* translation;
} code_name_pair_t;

// TODO:  Add ARP translation table and implement
extern const code_name_pair_t ip_translation_table[];
extern const code_name_pair_t icmp_translation_table[];
extern const code_name_pair_t eth_translation_table[];

const char* translate(Table_id table_id, int prot_num);
const char* lookup(const code_name_pair_t* table, size_t len, int code);

struct ethhdr* parse_ethernet(unsigned char* buf, ssize_t* bytes_remaining);
struct tcphdr* parse_tcp(struct iphdr* ip_header, ssize_t* bytes_remaining);
struct udphdr* parse_udp(struct iphdr* ip_header, ssize_t* bytes_remaining);
struct arphdr* parse_arp(struct ethhdr* eth_header, ssize_t* bytes_remaining);
struct iphdr* parse_ip(struct ethhdr* eth_header, ssize_t* bytes_remaining);
struct icmphdr* parse_icmp(struct iphdr* ip_header, ssize_t* bytes_remaining);

// liberally "burrowed" from /linux/if_arp.h and defined here for convenience.
struct arppld {
    unsigned char ar_sha[ETH_ALEN]; /* sender hardware address	*/
    unsigned char ar_sip[4];        /* sender IP address		*/
    unsigned char ar_tha[ETH_ALEN]; /* target hardware address	*/
    unsigned char ar_tip[4];        /* target IP address		*/
};

#endif
