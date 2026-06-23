


#include "packethound_utils.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 *
 *  TODO:  Maybe add a helper function which prints proper usage. Quite shoddy for now
 *  TODO:  Print statistics of protocol usage. 
 *  TODO:  Possible architectural overhaul. TBD. 
 *  TODO:  Passing around pointers to structs like that feels a little clunky, maybe rethink? 
 *  
 */


struct stats_block {
    unsigned int total_packet_count;
    unsigned int tcp_over_ip_count;
    unsigned int udp_over_ip_count;
    unsigned int icmp_count; 
    unsigned int arp_count;
};



int main(int argc, char** argv) {
    if (argc < 2) {
        printf("less than 2 args\n");
        return -1;
    }
    char* if_name = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
            case 'i':
                if_name = optarg;
                break;
            case '?':
                printf("unrecognized flag\n");
                break;
        }
    }

    if (if_name == NULL) {
        printf("Interface not provided.\neg. -i eth0\n");
        return -1;
    }

    unsigned char msg_buf[MAX_SIZE] = {0};

    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        fprintf(stderr, "socket failure\n");
        return -1;
    }

    unsigned int if_index = if_nametoindex(if_name);
    if (if_index == 0) {
        fprintf(stderr, "failed to index provided interface\n");
        return -1;
    }

    struct packet_mreq mreq = {
        .mr_ifindex = if_index,
        .mr_type = PACKET_MR_PROMISC,
    };

    if (setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
        fprintf(stderr, "setsockopt failure\n");
        return -1;
    }

    struct sockaddr_ll sockaddr_info = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = if_index,
    };

    if (bind(sock_fd, (struct sockaddr*)&sockaddr_info, sizeof(sockaddr_info)) < 0) {
        perror("Failed to bind");
        return -1;
    }

    struct stats_block stat_block = {0};

    while (true) {
        ssize_t bytes_remaining;

        memset(msg_buf, 0, MAX_SIZE);  // TODO: possibly workaround this. Most likely its overkill

        if ((bytes_remaining = recv(sock_fd, msg_buf, MAX_SIZE, 0)) == -1) {
            perror("recv failure");
            return -1;
        }

        struct ethhdr* eth_header;
        if ((eth_header = parse_ethernet(msg_buf, &bytes_remaining)) == NULL)
            continue;

        if (ntohs(eth_header->h_proto) == ETH_P_IP) {

            struct iphdr* ip_header;
            if((ip_header = parse_ip(eth_header, &bytes_remaining))==NULL)
                continue;

            switch (ip_header->protocol) {
                case PROTOCOL_TCP: {
                    struct tcphdr* tcp_header;
                    if ((tcp_header = parse_tcp(ip_header, &bytes_remaining)) == NULL)
                        continue;
                    stat_block.total_packet_count++;
                    stat_block.tcp_over_ip_count++;
                    break;
                }
                case PROTOCOL_UDP: {
                    struct udphdr* udp_header;
                    if ((udp_header = parse_udp(ip_header, &bytes_remaining)) == NULL)
                        continue;

                    stat_block.total_packet_count++;
                    stat_block.udp_over_ip_count++;
                    break;
                }
                case PROTOCOL_ICMP: {
                    struct icmphdr* icmp_header;
                    if ((icmp_header = parse_icmp(ip_header, &bytes_remaining)) == NULL)
                        continue;
                    stat_block.total_packet_count++;
                    stat_block.icmp_count++;
                    break;
                }
            }
        } else if (ntohs(eth_header->h_proto) == ETH_P_ARP) {
            struct arphdr* arp_header;
            if ((arp_header = parse_arp(eth_header, &bytes_remaining)) == NULL)
                continue;
            stat_block.total_packet_count++;
            stat_block.arp_count++;
        }
    }
}
