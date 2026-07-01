#include "packethound_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <net/if_arp.h>

const code_name_pair_t ip_translation_table[] = {
    {PROTOCOL_TCP, "TCP"},
    {PROTOCOL_UDP, "UDP"},
    {PROTOCOL_ICMP, "ICMP"},
};

const code_name_pair_t icmp_translation_table[] = {{ICMP_ECHO, "Echo Request"},
                                                   {ICMP_ECHOREPLY, "Echo Reply"}};

const code_name_pair_t eth_translation_table[] = {
    {ETH_P_IP,"IPv4"},
    {ETH_P_ARP,"ARP"},
    {ETH_P_IPV6	,"IPv6 over bluebook"},	
    {ETH_P_REALTEK,"Multiple proprietary protocols"}, 
    {ETH_P_LLDP,"Link Layer Discovery Protocol"}, 
    {ETH_P_CFM,"Connectivity Fault Management"}, 
    {ETH_P_LOOPBACK,"Ethernet loopback packet, per IEEE 802.3"}, 
};

const code_name_pair_t arp_translation_table[] = {
    {ARPOP_REQUEST, "ARP request"},		/* ARP request.  */
    {ARPOP_REPLY, "ARP reply"},		    /* ARP reply.  */
    {ARPOP_RREQUEST, "RARP request"},	/* RARP request.  */
    {ARPOP_RREPLY,	"RARP reply"},		/* RARP reply.  */
    {ARPOP_InREQUEST, "InARP request"},	/* InARP request.  */
    {ARPOP_InREPLY, "InARP reply"},		/* InARP reply.  */
    {ARPOP_NAK	, "(ATM) ARP NAK"},     /* (ATM)ARP NAK.  */
};

const char* translate(Table_id table_id, int prot_num) {
    switch (table_id) {
        case ETH:
            return lookup(eth_translation_table,
                          sizeof(eth_translation_table) / sizeof(eth_translation_table[0]),
                          prot_num);
        case IP:
            return lookup(ip_translation_table,
                          sizeof(ip_translation_table) / sizeof(ip_translation_table[0]), prot_num);
        case ICMP:
            return lookup(icmp_translation_table,
                          sizeof(icmp_translation_table) / sizeof(icmp_translation_table[0]),
                          prot_num);
        default:
            return "Case not handled yet";
    }
}
const char* lookup(const code_name_pair_t* table, size_t len, int code) {
    for (size_t i = 0; i < len; i++) {
        if (table[i].prot_code == code)
            return table[i].translation;
    }

    return "Translation not found";
}

struct ethhdr* parse_ethernet(unsigned char* buf, ssize_t* bytes_remaining) {

    //  NOTE:  I think im in the clear to cast bytes_remaining to size_t here. 
    //         The negative case is handled in main, might reconsider.
    if((size_t)*bytes_remaining < sizeof(struct ethhdr)){
        fprintf(stderr, "malformed eth header\n");
        return NULL;
    }

    struct ethhdr* eth_header = (struct ethhdr*)buf;

    printf("\n\nMAC_SRC=%02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->h_source[0],
           eth_header->h_source[1], eth_header->h_source[2], eth_header->h_source[3],
           eth_header->h_source[4], eth_header->h_source[5]);

    printf("MAC_DST=%02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->h_dest[0], eth_header->h_dest[1],
           eth_header->h_dest[2], eth_header->h_dest[3], eth_header->h_dest[4],
           eth_header->h_dest[5]);

    printf("Eth type : %04x (%s)\n", ntohs(eth_header->h_proto),
           translate(ETH, ntohs(eth_header->h_proto)));

    *bytes_remaining -= sizeof(struct ethhdr);

    return eth_header;
}

struct tcphdr* parse_tcp(struct iphdr* ip_header, ssize_t* bytes_remaining) {

    if((size_t) *bytes_remaining < sizeof(struct tcphdr)){
        fprintf(stderr, "malformed tcp header\n");
        return NULL;
    }
    struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + ip_header->ihl * 4);
    size_t tcp_doff_bytes = tcp_header->doff * 4;

    if((size_t)*bytes_remaining < tcp_doff_bytes ){
        fprintf(stderr,"malformed tcp header data\n");
        return NULL;
    }

    printf("TCP | Source address = %u\n", ntohs(tcp_header->source));
    printf("TCP | Destination address = %u\n", ntohs(tcp_header->dest));

    *bytes_remaining -= tcp_doff_bytes;

    return tcp_header;
}

struct iphdr* parse_ip(struct ethhdr* eth_header, ssize_t* bytes_remaining) {

    if((size_t)*bytes_remaining < sizeof(struct iphdr) ){
        fprintf(stderr, "malformed ip header\n");
        return NULL;
    }

    struct iphdr* ip_header = (struct iphdr*)((char*)eth_header + sizeof(struct ethhdr));
    size_t iphl = ip_header->ihl; 

    if(iphl < 5 ){
        fprintf(stderr, "malformed ip header length\n");
        return NULL;
    }

    iphl = iphl * 4; // To get the actual number of bytes of the header


    if((size_t)*bytes_remaining < iphl){
        fprintf(stderr, "malformed ip header options\n");
        return NULL;
    }

    struct in_addr inaddr;
    inaddr.s_addr = ip_header->saddr;

    struct in_addr outaddr;
    outaddr.s_addr = ip_header->daddr;

    printf("IP | Source IP address = %s\n", inet_ntoa(inaddr));
    printf("IP | Destination IP address = %s\n", inet_ntoa(outaddr));

    *bytes_remaining -= iphl;

    return ip_header;
}

struct udphdr* parse_udp(struct iphdr* ip_header, ssize_t* bytes_remaining) {

    if((size_t)*bytes_remaining < sizeof(struct udphdr)){

        fprintf(stderr,"malformed udp header\n");
        return NULL;
    }

    struct udphdr* udp_header = (struct udphdr*)((char*)ip_header + ip_header->ihl * 4);

    printf("UDP | Source port = %u\n", ntohs(udp_header->source));
    printf("UDP | Destination port = %u\n", ntohs(udp_header->dest));

    *bytes_remaining -= sizeof(struct udphdr);

    return udp_header;
}

struct arphdr* parse_arp(struct ethhdr* eth_header, ssize_t* bytes_remaining) {

    if((size_t)*bytes_remaining < sizeof(struct arphdr) + sizeof(struct arppld)){
        fprintf(stderr,"malformed arp header\n");
        return NULL;
    }

    struct arphdr* arp_header = (struct arphdr*)((char*)eth_header + sizeof(struct ethhdr));

    struct arppld* arp_payload = (struct arppld*)((char*)arp_header + sizeof(struct arphdr));

    struct in_addr sip_addr, tip_addr;

    memcpy(&sip_addr.s_addr, arp_payload->ar_sip, 4);
    memcpy(&tip_addr.s_addr, arp_payload->ar_tip, 4);

    printf("ARP | Source MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", arp_payload->ar_sha[0],
           arp_payload->ar_sha[1], arp_payload->ar_sha[2], arp_payload->ar_sha[3],
           arp_payload->ar_sha[4], arp_payload->ar_sha[5]);

    printf("ARP | Target MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", arp_payload->ar_tha[0],
           arp_payload->ar_tha[1], arp_payload->ar_tha[2], arp_payload->ar_tha[3],
           arp_payload->ar_tha[4], arp_payload->ar_tha[5]);

    printf("ARP | Source IP : %s\n", inet_ntoa(sip_addr));
    printf("ARP | Target IP : %s\n", inet_ntoa(tip_addr));

    *bytes_remaining -= sizeof(struct arphdr) + sizeof(struct arppld);

    return arp_header;
}

struct icmphdr* parse_icmp(struct iphdr* ip_header, ssize_t* bytes_remaining) {

    if((size_t)*bytes_remaining < sizeof(struct icmphdr)){

        fprintf(stderr,"malformed icmp header\n");
        return NULL;
    }

    struct icmphdr* icmp_header = (struct icmphdr*)((char*)ip_header + ip_header->ihl * 4);

    printf("ICMP | icmp_type = %u (%s), icmp_code = %u \n", icmp_header->type,
           translate(ICMP, icmp_header->type), icmp_header->code);

    if (icmp_header->type == ICMP_ECHO || icmp_header->type == ICMP_ECHOREPLY)
        printf("ICMP | icmp_echo_id = %u, icmp_echo_seq = %u\n", ntohs(icmp_header->un.echo.id),
               ntohs(icmp_header->un.echo.sequence));

    *bytes_remaining -= sizeof(struct icmphdr);

    return icmp_header;
}

