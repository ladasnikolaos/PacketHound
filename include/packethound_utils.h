#ifndef PHND_UTILS_H
#define PHND_UTILS_H



#include <stdint.h>
#include <stddef.h>

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


#endif
