#include "packethound_utils.h"

#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 *
 *  TODO:  Possible architectural overhaul. TBD. 
 *  TODO:  Passing around pointers to structs like that feels a little clunky, maybe rethink? 
 *  
 */

enum parse_result {
    BIND_INTERFACE_PROCEED=0,
    ERROR = 1,
    HELP = 2
};

struct stats_block {
    unsigned int total_packet_count;
    unsigned int tcp_over_ip_count;
    unsigned int udp_over_ip_count;
    unsigned int icmp_count; 
    unsigned int arp_count;
};


volatile sig_atomic_t sigint_not_received = 1;

void sigint_handler(int signal){
    (void) signal; 
    sigint_not_received = 0;
}


void print_help(void) {
    printf("Usage: phound [OPTIONS]\n" 
           "OPTIONS:\n"
           "-i <interface> | Interface to use | eg. -i eth0\n"
           "-h             | Displays this help message\n"
           );
}

enum parse_result parse_args(int argc, char** argv, char** if_name){
    bool h_seen = false, i_seen = false; 
    int opt;

    if (argc < 2) {
        return ERROR;
    }

    while ((opt = getopt(argc, argv, ":i:h")) != -1) {
        switch (opt) {
            case 'i':
                *if_name = optarg;
                i_seen = true;
                break;
            case 'h':
                h_seen = true;
                break;
            case '?':
                fprintf(stderr, "Unrecognized flag '-%c'\n", optopt);
                return ERROR;
            case ':':
                fprintf(stderr, "Flag '-%c' required an argument.\n", optopt);
                return ERROR;
        }
    }

    if(i_seen && h_seen){
        fprintf(stderr, "'-i' and '-h' cant be used together.\n");
        return ERROR;
    } else if (h_seen){
        return HELP;
    } else if (!i_seen) {
        fprintf(stderr, "Interface not provided.\n");
        return ERROR;
    } else
        return BIND_INTERFACE_PROCEED;
}


int init_socket(int* socket_fd, char* if_name){

    *socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (*socket_fd < 0) {
        perror("socket failure");
        return -1;
    }

    unsigned int if_index = if_nametoindex(if_name);

    if (if_index == 0) {
        perror("failed to index provided interface");
        return -1;
    }

    struct packet_mreq mreq = {
        .mr_ifindex = if_index,
        .mr_type = PACKET_MR_PROMISC,
    };

    if (setsockopt(*socket_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
        perror("setsockopt failure");
        return -1;
    }

    struct sockaddr_ll sockaddr_info = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = if_index,
    };

    if (bind(*socket_fd, (struct sockaddr*)&sockaddr_info, sizeof(sockaddr_info)) < 0) {
        perror("Failed to bind");
        return -1;
    }

    return 0;
}

int init_sigaction(){

    struct sigaction sig_action;
    sig_action.sa_handler = sigint_handler; 
    sigemptyset(&sig_action.sa_mask);

    if(sigaction(SIGINT, &sig_action, NULL) == -1){
        perror("sigaction failure");
        return -1;
    }
    return 0;
}

int main(int argc, char** argv) {

    char* if_name = NULL;
    int socket_fd = -1; // just to be safe

    enum parse_result result = parse_args(argc, argv, &if_name);

    switch(result){
        case HELP:
            print_help();
            return 0;
            break;
        case BIND_INTERFACE_PROCEED:
            if(init_socket(&socket_fd, if_name) == -1)
                return -1;
            if(init_sigaction() == -1)
                return -1;
            break;
        case ERROR:
            fprintf(stderr, "Usage: phound [OPTIONS]\nTry 'phound -h' for more information.\n");
            return -1; 
    }


    unsigned char msg_buf[IP_MAXPACKET] = {0};
    struct stats_block stat_block = {0};

    while (sigint_not_received) {
        ssize_t bytes_remaining;

        if ((bytes_remaining = recv(socket_fd, msg_buf, IP_MAXPACKET, 0)) == -1) {
            if(errno == EINTR)
                continue;

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

    printf("\n================================================\n");
    printf("Session stats :\n"
           "\tTotal Amount of Packets processed : %u\n"
           "\tTCP/IP packets : %u\n"
           "\tUDP/IP packets : %u\n"
           "\tICMP packets : %u\n"
           "\tARP packets : %u\n",
           stat_block.total_packet_count,
           stat_block.tcp_over_ip_count,
           stat_block.udp_over_ip_count,
           stat_block.icmp_count,
           stat_block.arp_count
           );

}
