#include "arp.h"


const char* get_ethertype_name(uint16_t type) {
    if (type <= 0x05DC) {
        return "IEEE802.3 Length Field";
    }
    if (type >= 0x0101 && type <= 0x01FF) {
        return "Old Xerox Experimental values (invalid since 1983)";
    }
    if (type >= 0x1001 && type <= 0x100F) {
        return "Berkeley Trailer encap/IP";
    }
    if (type >= 0x6008 && type <= 0x6009) {
        return "DEC Unassigned";
    }
    if (type >= 0x6010 && type <= 0x6014) {
        return "3Com Corporation";
    }
    if (type >= 0x7020 && type <= 0x7029) {
        return "LRT";
    }
    if (type >= 0x8039 && type <= 0x803C) {
        return "DEC Unassigned";
    }
    if (type >= 0x8040 && type <= 0x8042) {
        return "DEC Unassigned";
    }
    if (type >= 0x806E && type <= 0x8077) {
        return "Landmark Graphics Corp.";
    }
    if (type >= 0x807D && type <= 0x807F) {
        return "Vitalink Communications";
    }
    if (type >= 0x8081 && type <= 0x8083) {
        return "Counterpoint Computers";
    }
    if (type >= 0x809C && type <= 0x809E) {
        return "Datability";
    }
    if (type >= 0x80A4 && type <= 0x80B3) {
        return "Siemens Gammasonics Inc.";
    }
    if (type >= 0x80C0 && type <= 0x80C3) {
        return "DCA Data Exchange Cluster";
    }
    if (type >= 0x80C8 && type <= 0x80CC) {
        return "Intergraph Corporation";
    }
    if (type >= 0x80CD && type <= 0x80CE) {
        return "Harris Corporation";
    }
    if (type >= 0x80CF && type <= 0x80D2) {
        return "Taylor Instrument";
    }
    if (type >= 0x80D3 && type <= 0x80D4) {
        return "Rosemount Corporation";
    }
    if (type >= 0x80DE && type <= 0x80DF) {
        return "Integrated Solutions TRFS";
    }
    if (type >= 0x80E0 && type <= 0x80E3) {
        return "Allen-Bradley";
    }
    if (type >= 0x80E4 && type <= 0x80F0) {
        return "Datability";
    }
    if (type >= 0x80F4 && type <= 0x80F5) {
        return "Kinetics";
    }
    if (type >= 0x8101 && type <= 0x8103) {
        return "Wellfleet Communications";
    }
    if (type >= 0x8107 && type <= 0x8109) {
        return "Symbolics Private";
    }
    if (type >= 0x8132 && type <= 0x8136) {
        return "Bridge Communications";
    }
    if (type >= 0x8139 && type <= 0x813D) {
        return "KTI";
    }
    if (type >= 0x8151 && type <= 0x8153) {
        return "Qualcomm";
    }
    if (type >= 0x815C && type <= 0x815E) {
        return "Computer Protocol Pty Ltd";
    }
    if (type >= 0x8164 && type <= 0x8166) {
        return "Charles River Data System";
    }
    if (type >= 0x8184 && type <= 0x818C) {
        return "Silicon Graphics prop.";
    }
    if (type >= 0x819A && type <= 0x81A3) {
        return "Qualcomm";
    }
    if (type >= 0x81A5 && type <= 0x81AE) {
        return "RAD Network Devices";
    }
    if (type >= 0x81B7 && type <= 0x81B9) {
        return "Xyplex";
    }
    if (type >= 0x81CC && type <= 0x81D5) {
        return "Apricot Computers";
    }
    if (type >= 0x81D6 && type <= 0x81DD) {
        return "Artisoft";
    }
    if (type >= 0x81E6 && type <= 0x81EF) {
        return "Polygon";
    }
    if (type >= 0x81F0 && type <= 0x81F2) {
        return "Comsat Labs";
    }
    if (type >= 0x81F3 && type <= 0x81F5) {
        return "SAIC";
    }
    if (type >= 0x81F6 && type <= 0x81F8) {
        return "VG Analytical";
    }
    if (type >= 0x8203 && type <= 0x8205) {
        return "Quantum Software";
    }
    if (type >= 0x8221 && type <= 0x8222) {
        return "Ascom Banking Systems";
    }
    if (type >= 0x823E && type <= 0x8240) {
        return "Advanced Encryption Syste";
    }
    if (type >= 0x8263 && type <= 0x826A) {
        return "Charles River Data System";
    }
    if (type >= 0x827F && type <= 0x8282) {
        return "Athena Programming";
    }
    if (type >= 0x829A && type <= 0x829B) {
        return "Inst Ind Info Tech";
    }
    if (type >= 0x829C && type <= 0x82AB) {
        return "Taurus Controls";
    }
    if (type >= 0x82AC && type <= 0x8693) {
        return "Walker Richer & Quinn";
    }
    if (type >= 0x8694 && type <= 0x869D) {
        return "Idea Courier";
    }
    if (type >= 0x869E && type <= 0x86A1) {
        return "Computer Network Tech";
    }
    if (type >= 0x86A3 && type <= 0x86AC) {
        return "Gateway Communications";
    }
    if (type >= 0x86E0 && type <= 0x86EF) {
        return "Landis & Gyr Powers";
    }
    if (type >= 0x8700 && type <= 0x8710) {
        return "Motorola";
    }
    if (type >= 0x8A96 && type <= 0x8A97) {
        return "Invisible Software";
    }
    if (type >= 0xFF00 && type <= 0xFF0F) {
        return "ISC Bunker Ramo private protocol";
    }
    
        if (ethertype_names[type] != NULL) {
            return ethertype_names[type];
        }
    
    return "Unknown EtherType";
}

const char* get_hardware_type_name(uint16_t type) {
    if (type >= 39 && type <= 255) return "Unassigned";
    if (type >= 258 && type <= 65534) return "Unassigned";
    
        if (hardware_types[type] != NULL) {
            return hardware_types[type];
        }

    if (type == 65535) return hardware_types[65535];
    
    return "Unknown";
}

const char* get_arp_operation_name(uint16_t op) {
    if (op >= 26 && op <= 65534) return "Unassigned";
    
        if (operation_types[op] != NULL) {
            return operation_types[op];
        }
    
    if (op == 65535) return operation_types[65535];
    
    return "Unknown operation";
}

int parse_arp(const uint8_t *data, size_t len, struct arp_packet *packet) {
    if (data == NULL || packet == NULL || len < sizeof(struct arp_packet)) {
        return -1;
    }
    packet->htype = (data[0] << 8) | data[1];
    packet->ptype = (data[2] << 8) | data[3];
    packet->hsize = data[4];
    packet->psize = data[5];
    packet->op = (data[6] << 8) | data[7];

    const uint8_t *src_ptr = &data[8];
    uint8_t *dst_ptr = packet->sha;
    for (int i = 0; i < 20; i++) {
        *dst_ptr++ = *src_ptr++;
    }
    return 0;
}

void print_arp(const struct arp_packet *packet) {
    if (packet == NULL) {
        printf("ARP Packet: NULL pointer\n");
        return;
    }
    printf("ARP Packet:\n");
    printf("  Hardware type: %s (0x%04X)\n", 
           get_hardware_type_name(packet->htype), packet->htype);
    
    printf("  Protocol type: %s (0x%04X)\n", 
           get_ethertype_name(packet->ptype), packet->ptype);
    
    printf("  Hardware size: %u\n", 
           packet->hsize);
    
    printf("  Protocol size: %u\n", 
           packet->psize);
    
    printf("  Operation: %s (0x%04X)\n", 
           get_arp_operation_name(packet->op),
            packet->op
           );
    printf("  Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           packet->sha[0], packet->sha[1], packet->sha[2], 
           packet->sha[3], packet->sha[4], packet->sha[5]);
    printf("  Sender IP address: %u.%u.%u.%u\n", 
           packet->spa[0], packet->spa[1], packet->spa[2], packet->spa[3]);
    printf("  Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           packet->tha[0], packet->tha[1], packet->tha[2], 
           packet->tha[3], packet->tha[4], packet->tha[5]);
    printf("  Target IP address: %u.%u.%u.%u\n", 
           packet->tpa[0], packet->tpa[1], packet->tpa[2], packet->tpa[3]);
}

