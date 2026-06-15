#include "packethound_utils.h"

const code_name_pair_t ip_translation_table[] = {
    {PROTOCOL_TCP, "TCP"},
    {PROTOCOL_UDP, "UDP"},
    {PROTOCOL_ICMP, "ICMP"},
};

const code_name_pair_t icmp_translation_table[] = {{ICMP_ECHO, "Echo Request"},
                                                   {ICMP_ECHOREPLY, "Echo Reply"}};

const code_name_pair_t eth_translation_table[] = {
    {ETH_P_IP, "IPv4"},
    {ETH_P_ARP, "ARP"},
};

const char* translate(Table_id table_id, int prot_num) {
    // TODO: Add ARP handling
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
