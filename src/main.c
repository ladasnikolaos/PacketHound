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
 *  TODO:  Maybe add a helper function which prints proper usage.
 *
 */

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

    while (true) {
        ssize_t restof_bytes;

        memset(msg_buf, 0, MAX_SIZE);  // mayb workaround this. Possibly overkill

        if ((restof_bytes = recv(sock_fd, msg_buf, MAX_SIZE, 0)) == -1) {
            perror("recv failure");
            return -1;
        }

        struct ethhdr* eth_header;
        if ((eth_header = parse_ethernet(msg_buf, &restof_bytes)) == NULL)
            continue;

        if (ntohs(eth_header->h_proto) == ETH_P_IP) {

            struct iphdr* ip_header;
            if((ip_header = parse_ip(eth_header, &restof_bytes))==NULL)
                continue;

            switch (ip_header->protocol) {
                case PROTOCOL_TCP: {
                    struct tcphdr* tcp_header;
                    if ((tcp_header = parse_tcp(ip_header, &restof_bytes)) == NULL)
                        continue;
                    break;
                }
                case PROTOCOL_UDP: {
                    struct udphdr* udp_header;
                    if ((udp_header = parse_udp(ip_header, &restof_bytes)) == NULL)
                        continue;
                    break;
                }
                case PROTOCOL_ICMP: {
                    struct icmphdr* icmp_header;
                    if ((icmp_header = parse_icmp(ip_header, &restof_bytes)) == NULL)
                        continue;
                    break;
                }
            }
        } else if (ntohs(eth_header->h_proto) == ETH_P_ARP) {
            struct arphdr* arp_header;
            if ((arp_header = parse_arp(eth_header, &restof_bytes)) == NULL)
                continue;
        }
    }
}
