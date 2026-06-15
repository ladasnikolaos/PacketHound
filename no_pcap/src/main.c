#include "packethound_utils.h"

#include <arpa/inet.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    char msg_buf[MAX_SIZE] = {0};

    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket failure\n");
        return -1;
    }

    while (true) {
        memset(msg_buf, 0, MAX_SIZE);

        if (recv(sock_fd, msg_buf, MAX_SIZE, 0) == -1) {
            perror("recv failure\n");
            return -1;
        }

        struct ethhdr* eth_header = (struct ethhdr*)msg_buf;

        printf("\n\nMAC_SRC=%02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->h_source[0],
               eth_header->h_source[1], eth_header->h_source[2], eth_header->h_source[3],
               eth_header->h_source[4], eth_header->h_source[5]);

        printf("MAC_DST=%02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->h_dest[0], eth_header->h_dest[1],
               eth_header->h_dest[2], eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);

        printf("Eth type : %04x (%s)\n", ntohs(eth_header->h_proto),
               translate(ETH, ntohs(eth_header->h_proto)));

        if (ntohs(eth_header->h_proto) == ETH_P_IP) {
            struct iphdr* ip_header = (struct iphdr*)(msg_buf + sizeof(struct ethhdr));

            struct in_addr inaddr;
            inaddr.s_addr = ip_header->saddr;

            struct in_addr outaddr;
            outaddr.s_addr = ip_header->daddr;

            printf("IP | Source IP address = %s\n", inet_ntoa(inaddr));
            printf("IP | Destination IP address = %s\n", inet_ntoa(outaddr));

            switch (ip_header->protocol) {
                case PROTOCOL_TCP: {
                    struct tcphdr* tcp_header =
                        (struct tcphdr*)((char*)ip_header + ip_header->ihl * 4);

                    printf("TCP | Source address = %u\n", ntohs(tcp_header->source));
                    printf("TCP | Destination address = %u\n", ntohs(tcp_header->dest));
                    break;
                }
                case PROTOCOL_UDP: {
                    struct udphdr* udp_header =
                        (struct udphdr*)((char*)ip_header + ip_header->ihl * 4);
                    printf("UDP | Source port = %u\n", ntohs(udp_header->source));
                    printf("UDP | Destination port = %u\n", ntohs(udp_header->dest));
                    break;
                }
                case PROTOCOL_ICMP: {
                    struct icmphdr* icmp_header =
                        (struct icmphdr*)((char*)ip_header + ip_header->ihl * 4);
                    printf("ICMP | icmp_type = %u (%s), icmp_code = %u \n", icmp_header->type,
                           translate(ICMP, icmp_header->type), icmp_header->code);

                    if (icmp_header->type == ICMP_ECHO || icmp_header->type == ICMP_ECHOREPLY)
                        printf("ICMP | icmp_echo_id = %u, icmp_echo_seq = %u\n",
                               ntohs(icmp_header->un.echo.id),
                               ntohs(icmp_header->un.echo.sequence));

                    break;
                }
            }
        } else if (ntohs(eth_header->h_proto) == ETH_P_ARP) {
            /*    NOTE: For the time being, arp_header exists only to compute the way to the
             *    payload, might utilize the info here later.
             */
            struct arphdr* arp_header = (struct arphdr*)(msg_buf + sizeof(struct ethhdr));

            struct arppld* arp_payload =
                (struct arppld*)((char*)arp_header + sizeof(struct arphdr));

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
        }
    }
}
