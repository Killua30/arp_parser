#ifndef S21_ARP_H
#define S21_ARP_H
#include <stdint.h>
#include <stdio.h>
#include "arp_types.h"

struct arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hsize;
    uint8_t psize;
    uint16_t op;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
};


const char* get_hardware_type_name(uint16_t type);
const char* get_ethertype_name(uint16_t type);
const char* get_arp_operation_name(uint16_t op);
int parse_arp(const uint8_t *data, size_t len, struct arp_packet *packet);
void print_arp(const struct arp_packet *packet);

#endif