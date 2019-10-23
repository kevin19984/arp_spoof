#pragma once

void makearp(uint8_t *packet, uint8_t *ether_shost, uint8_t *ether_dhost, uint16_t ether_type, uint16_t ar_hrd, uint16_t ar_pro, uint8_t ar_hln, uint8_t ar_pln, uint16_t ar_op, uint8_t *arp_sha, uint32_t arp_spa, uint8_t * arp_tha, uint32_t arp_tpa);
void makeRelaypacket(const u_char *packet, int len, uint8_t *relayippacket, uint8_t *attackermac, uint8_t *targetmac);

