#include <arpa/inet.h>
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

#define MAX_SIZE 65534

#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

// liberally "burrowed" from /linux/if_arp.h and defined here for convenience.
struct arppld {
    unsigned char ar_sha[ETH_ALEN]; /* sender hardware address	*/
    unsigned char ar_sip[4];        /* sender IP address		*/
    unsigned char ar_tha[ETH_ALEN]; /* target hardware address	*/
    unsigned char ar_tip[4];        /* target IP address		*/
};

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

        struct ethhdr* received = (struct ethhdr*)msg_buf;

        printf("\n\nMAC_SRC=%02x:%02x:%02x:%02x:%02x:%02x\n", received->h_source[0],
               received->h_source[1], received->h_source[2], received->h_source[3],
               received->h_source[4], received->h_source[5]);

        printf("MAC_DST=%02x:%02x:%02x:%02x:%02x:%02x\n", received->h_dest[0], received->h_dest[1],
               received->h_dest[2], received->h_dest[3], received->h_dest[4], received->h_dest[5]);

        printf("Eth type : %04x\n", ntohs(received->h_proto));

        if (ntohs(received->h_proto) == ETH_P_IP) {
            struct iphdr* ip_header = (struct iphdr*)(msg_buf + sizeof(struct ethhdr));

            struct in_addr inaddr;
            inaddr.s_addr = ip_header->saddr;

            struct in_addr outaddr;
            outaddr.s_addr = ip_header->daddr;

            printf("Source IP address = %s\n", inet_ntoa(inaddr));
            printf("Destination IP address = %s\n", inet_ntoa(outaddr));

            switch (ip_header->protocol) {
                case PROTOCOL_TCP:{
                    struct tcphdr* tcp_header =
                        (struct tcphdr*)((char*)ip_header + ip_header->ihl * 4);

                    printf("TCP | Source address = %u\n", ntohs(tcp_header->source));
                    printf("TCP | Destination address = %u\n", ntohs(tcp_header->dest));
                    break;
                }
                case PROTOCOL_UDP:{
                    struct udphdr* udp_header =
                        (struct udphdr*)((char*)ip_header + ip_header->ihl * 4);
                    printf("UDP | Source port = %u\n", ntohs(udp_header->source));
                    printf("UDP | Destination port = %u\n", ntohs(udp_header->dest));
                    break;
                }
            }
        } else if (ntohs(received->h_proto) == ETH_P_ARP) {
            /*    TODO: For the time exists only to compute the way to the payload,
             *          might utilize the info here later. 
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
