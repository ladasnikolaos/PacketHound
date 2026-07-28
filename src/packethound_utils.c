#include "packethound_utils.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <net/if_arp.h>


static const char* lookup(const code_name_pair* table, size_t len, int code);
typedef enum {
    TABLE_ETH = 0,
    TABLE_IP = 1,
    TABLE_ARP = 2,
    TABLE_ICMP = 3,
} Table_id;


struct iterator{
    size_t bytes_remaining;
    const uint8_t* rd_ptr;
};

const code_name_pair ip_translation_table[] = {
    {IPPROTO_TCP, "TCP"},
    {IPPROTO_UDP, "UDP"},
    {IPPROTO_ICMP, "ICMP"},
};

const code_name_pair icmp_translation_table[] = {{ICMP_ECHO, "Echo Request"},
                                                   {ICMP_ECHOREPLY, "Echo Reply"}};

const code_name_pair eth_translation_table[] = {
    {ETH_P_IP,"IPv4"},
    {ETH_P_ARP,"ARP"},
    {ETH_P_IPV6	,"IPv6 over bluebook"},	
    {ETH_P_REALTEK,"Multiple proprietary protocols"}, 
    {ETH_P_LLDP,"Link Layer Discovery Protocol"}, 
    {ETH_P_CFM,"Connectivity Fault Management"}, 
    {ETH_P_LOOPBACK,"Ethernet loopback packet, per IEEE 802.3"}, 
};

const code_name_pair arp_translation_table[] = {
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
        case TABLE_ETH:
            return lookup(eth_translation_table,
                          sizeof(eth_translation_table) / sizeof(eth_translation_table[0]),
                          prot_num);
        case TABLE_IP:
            return lookup(ip_translation_table,
                          sizeof(ip_translation_table) / sizeof(ip_translation_table[0]), 
                          prot_num);
        case TABLE_ICMP:
            return lookup(icmp_translation_table,
                          sizeof(icmp_translation_table) / sizeof(icmp_translation_table[0]),
                          prot_num);
        case TABLE_ARP: 
            return lookup(arp_translation_table, 
                          sizeof(arp_translation_table) / sizeof(arp_translation_table[0]), 
                          prot_num);
        default:
            return "Case not handled yet";
    }
}

const char* lookup(const code_name_pair* table, size_t len, int code) {
    for (size_t i = 0; i < len; i++) {
        if (table[i].prot_code == code)
            return table[i].translation;
    }

    return "Translation not found";
}

parse_packet_result parse_ethernet(struct iterator*  iter, uint16_t* eth_proto) {

    if(iter->bytes_remaining< sizeof(struct ethhdr)){
        fprintf(stderr, "malformed eth header\n");
        return PARSE_PACKET_FAILURE;
    }

    struct ethhdr eth_header = {0};
    memcpy(&eth_header,iter->rd_ptr,sizeof(struct ethhdr));

    printf("\n\nMAC_SRC=%02x:%02x:%02x:%02x:%02x:%02x\n", eth_header.h_source[0],
           eth_header.h_source[1], eth_header.h_source[2], eth_header.h_source[3],
           eth_header.h_source[4], eth_header.h_source[5]);

    printf("MAC_DST=%02x:%02x:%02x:%02x:%02x:%02x\n", eth_header.h_dest[0], eth_header.h_dest[1],
           eth_header.h_dest[2], eth_header.h_dest[3], eth_header.h_dest[4],
           eth_header.h_dest[5]);

    *eth_proto = ntohs(eth_header.h_proto);
    printf("Eth type : %04x (%s)\n", *eth_proto,
           translate(TABLE_ETH, ntohs(eth_header.h_proto)));

    iter->rd_ptr += sizeof(struct ethhdr);
    iter->bytes_remaining -= sizeof(struct ethhdr);

    return PARSE_PACKET_SUCCESS;
}

parse_packet_result parse_tcp(struct iterator*  iter) {

    if( iter->bytes_remaining < sizeof(struct tcphdr)){
        fprintf(stderr, "malformed tcp header\n");
        return PARSE_PACKET_FAILURE;
    }
    struct tcphdr tcp_header = {0};
    memcpy(&tcp_header,iter->rd_ptr,sizeof(struct tcphdr));


    if(tcp_header.doff < 5){
        fprintf(stderr,"malformed tcp header data\n");
        return PARSE_PACKET_FAILURE;
    }

    size_t tcp_doff_bytes = tcp_header.doff * 4;


    if(iter->bytes_remaining < tcp_doff_bytes ){
        fprintf(stderr,"malformed tcp header data\n");
        return PARSE_PACKET_FAILURE;
    }

    printf("TCP | Source address = %u\n", ntohs(tcp_header.source));
    printf("TCP | Destination address = %u\n", ntohs(tcp_header.dest));

    iter->bytes_remaining -= tcp_doff_bytes;
    iter->rd_ptr += tcp_doff_bytes;

    return PARSE_PACKET_SUCCESS;
}

parse_packet_result parse_ip(struct iterator*  iter, uint8_t* ip_proto) {

    if(iter->bytes_remaining< sizeof(struct iphdr) ){
        fprintf(stderr, "malformed ip header\n");
        return PARSE_PACKET_FAILURE;
    }

    struct iphdr ip_header = {0};
    memcpy(&ip_header,iter->rd_ptr,sizeof(struct iphdr));
    size_t iphl = ip_header.ihl; 


    if(iphl < 5 ){
        fprintf(stderr, "malformed ip header length\n");
        return PARSE_PACKET_FAILURE;
    }

    iphl = iphl * 4; // To get the actual number of bytes of the header


    if(iter->bytes_remaining < iphl){
        fprintf(stderr, "malformed ip header options\n");
        return PARSE_PACKET_FAILURE;
    }


    *ip_proto = ip_header.protocol;

    struct in_addr inaddr;
    inaddr.s_addr = ip_header.saddr;

    struct in_addr outaddr;
    outaddr.s_addr = ip_header.daddr;

    printf("IP | Source IP address = %s\n", inet_ntoa(inaddr));
    printf("IP | Destination IP address = %s\n", inet_ntoa(outaddr));

    iter->bytes_remaining -= iphl;
    iter->rd_ptr+=iphl;

    return PARSE_PACKET_SUCCESS;
}

parse_packet_result parse_udp(struct iterator* iter) {

    if(iter->bytes_remaining< sizeof(struct udphdr)){

        fprintf(stderr,"malformed udp header\n");
        return PARSE_PACKET_FAILURE;
    }

    struct udphdr udp_header = {0};
    memcpy(&udp_header, iter->rd_ptr, sizeof(struct udphdr));


    printf("UDP | Source port = %u\n", ntohs(udp_header.source));
    printf("UDP | Destination port = %u\n", ntohs(udp_header.dest));

    iter->bytes_remaining -= sizeof(struct udphdr);
    iter->rd_ptr += sizeof(struct udphdr);

    return PARSE_PACKET_SUCCESS;
}

parse_packet_result parse_arp(struct iterator* iter) {

    if(iter->bytes_remaining < sizeof(struct arphdr) + sizeof(struct arppld)){
        fprintf(stderr,"malformed arp header\n");
        return PARSE_PACKET_FAILURE;
    }

    struct arphdr arp_header = {0};
    memcpy(&arp_header,iter->rd_ptr,sizeof(struct arphdr));

    iter->rd_ptr += sizeof(struct arphdr);
    iter->bytes_remaining -= sizeof(struct arphdr);

    struct arppld arp_payload = {0};
    memcpy(&arp_payload,iter->rd_ptr,sizeof(struct arppld));

    iter->rd_ptr += sizeof(struct arppld);
    iter->bytes_remaining -= sizeof(struct arppld);


    struct in_addr sip_addr, tip_addr;

    memcpy(&sip_addr.s_addr, arp_payload.ar_sip, 4);
    memcpy(&tip_addr.s_addr, arp_payload.ar_tip, 4);

    printf("ARP | Source MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", arp_payload.ar_sha[0],
           arp_payload.ar_sha[1], arp_payload.ar_sha[2], arp_payload.ar_sha[3],
           arp_payload.ar_sha[4], arp_payload.ar_sha[5]);

    printf("ARP | Target MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", arp_payload.ar_tha[0],
           arp_payload.ar_tha[1], arp_payload.ar_tha[2], arp_payload.ar_tha[3],
           arp_payload.ar_tha[4], arp_payload.ar_tha[5]);

    printf("ARP | Source IP : %s\n", inet_ntoa(sip_addr));
    printf("ARP | Target IP : %s\n", inet_ntoa(tip_addr));

    uint16_t opcode = ntohs(arp_header.ar_op);
    printf("ARP | opcode = %u (%s)\n", opcode, translate(TABLE_ARP, opcode));

    return PARSE_PACKET_SUCCESS;
}

parse_packet_result parse_icmp(struct iterator* iter) {

    if(iter->bytes_remaining < sizeof(struct icmphdr)){

        fprintf(stderr,"malformed icmp header\n");
        return PARSE_PACKET_FAILURE;
    }

    struct icmphdr icmp_header = {0};
    memcpy(&icmp_header,iter->rd_ptr,sizeof(struct icmphdr));

    printf("ICMP | icmp_type = %u (%s), icmp_code = %u \n", icmp_header.type,
           translate(TABLE_ICMP, icmp_header.type), icmp_header.code);

    if (icmp_header.type == ICMP_ECHO || icmp_header.type == ICMP_ECHOREPLY)
        printf("ICMP | icmp_echo_id = %u, icmp_echo_seq = %u\n", ntohs(icmp_header.un.echo.id),
               ntohs(icmp_header.un.echo.sequence));


    iter->rd_ptr += sizeof(struct icmphdr);
    iter->bytes_remaining -= sizeof(struct icmphdr);

    return PARSE_PACKET_SUCCESS;
}



parse_packet_result parse_packet(const uint8_t *data, size_t bytes, packet_category* categ){

        struct iterator iter = {
            .bytes_remaining = bytes,
            .rd_ptr = data 
        };

        uint16_t eth_proto;

        if ((parse_ethernet(&iter, &eth_proto)) == PARSE_PACKET_FAILURE)
            return PARSE_PACKET_FAILURE;

        if (eth_proto == ETH_P_IP) {

            uint8_t ip_proto;
            if((parse_ip(&iter,&ip_proto))== PARSE_PACKET_FAILURE)
                return PARSE_PACKET_FAILURE;

            switch (ip_proto) {
                case IPPROTO_TCP: {
                    if ((parse_tcp(&iter)) == PARSE_PACKET_FAILURE)
                        return PARSE_PACKET_FAILURE;
                    *categ = PACKET_CATEGORY_TCP_OVER_IP;
                    return PARSE_PACKET_SUCCESS;
                }
                case IPPROTO_UDP: {
                    if ((parse_udp(&iter)) == PARSE_PACKET_FAILURE)
                        return PARSE_PACKET_FAILURE;
                    *categ = PACKET_CATEGORY_UDP_OVER_IP;
                    return PARSE_PACKET_SUCCESS;
                }
                case IPPROTO_ICMP: {
                    if ((parse_icmp(&iter)) == PARSE_PACKET_FAILURE)
                        return PARSE_PACKET_FAILURE;
                    *categ = PACKET_CATEGORY_ICMP;
                    return PARSE_PACKET_SUCCESS;
                }
            default :
                *categ = PACKET_CATEGORY_NOT_HANDLED;
                return PARSE_PACKET_SUCCESS;
            }
        }
        else if (eth_proto == ETH_P_ARP) {
                if ((parse_arp(&iter)) == PARSE_PACKET_FAILURE)
                    return PARSE_PACKET_FAILURE;
                *categ = PACKET_CATEGORY_ARP;
                return PARSE_PACKET_SUCCESS;
            } 
        else{
            *categ = PACKET_CATEGORY_NOT_HANDLED;
            return PARSE_PACKET_SUCCESS;
        }
}
