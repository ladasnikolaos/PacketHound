#include <arpa/inet.h>
#include <string.h>
#include <udp.h>
#include <tcp.h>
#include <linux/if_ether.h>
#include <stdbool.h>
#include <linux/ip.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_SIZE 65534

int main() {
    char msg_buf[MAX_SIZE] = {0};

    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0)
        perror("socket failure\n");

    while (true) {
        memset(msg_buf,0,MAX_SIZE);

        if (recv(sock_fd, msg_buf, MAX_SIZE, 0) == -1)
            perror("recv failure\n");

        struct ethhdr* received = (struct ethhdr*)msg_buf;

        printf("\n\nMAC_SRC=%02x:%02x:%02x:%02x:%02x:%02x\n",
               received->h_source[0], received->h_source[1], 
               received->h_source[2], received->h_source[3],
               received->h_source[4], received->h_source[5]);

        printf("MAC_DST=%02x:%02x:%02x:%02x:%02x:%02x\n", 
               received->h_dest[0], received->h_dest[1],
               received->h_dest[2], received->h_dest[3], 
               received->h_dest[4], received->h_dest[5]);

        printf("Eth type : %04x\n", ntohs(received->h_proto));

        if (ntohs(received->h_proto) == ETH_P_IP) {
            struct iphdr* ip_header = (struct iphdr*)(msg_buf + sizeof(struct ethhdr));

            struct in_addr inaddr;
            inaddr.s_addr = ip_header->saddr;

            struct in_addr outaddr;
            outaddr.s_addr = ip_header->daddr;

            printf("Source IP address = %s\n", inet_ntoa(inaddr));
            printf("Destination IP address = %s\n", inet_ntoa(outaddr));
            printf("Protocol used: %u\n", ip_header->protocol);
        }
    }
}
