#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include "editpacket.h"
#include "arpheader.h"

void makearp(uint8_t *packet, uint8_t *ether_dhost, uint8_t *ether_shost, uint16_t ether_type, uint16_t ar_hrd, uint16_t ar_pro, uint8_t ar_hln, uint8_t ar_pln, uint16_t ar_op, uint8_t *arp_sha, uint32_t arp_spa, uint8_t * arp_tha, uint32_t arp_tpa)
{
  etherarp temp;
  memcpy(temp.eth.ether_shost, ether_shost, ETH_ALEN);
  memcpy(temp.eth.ether_dhost, ether_dhost, ETH_ALEN);
  temp.eth.ether_type = htons(ether_type);
  temp.arp.arp_hrd = htons(ar_hrd);
  temp.arp.arp_pro = htons(ar_pro);
  temp.arp.arp_hln = ar_hln;
  temp.arp.arp_pln = ar_pln;
  temp.arp.arp_op = htons(ar_op);
  memcpy(temp.arp.arp_sha, arp_sha, ETH_ALEN);
  temp.arp.arp_spa = arp_spa;
  memcpy(temp.arp.arp_tha, arp_tha, ETH_ALEN);
  temp.arp.arp_tpa = arp_tpa;
  memcpy(packet, &temp, ETH_HLEN + 28);
}

void makeRelaypacket(const u_char *packet, int len, uint8_t *relayippacket, uint8_t *attackermac, uint8_t *targetmac)
{
  ether_header eth;
  memcpy(&eth, packet, ETH_HLEN);
  memcpy(eth.ether_shost, attackermac, ETH_ALEN);
  memcpy(eth.ether_dhost, targetmac, ETH_ALEN);
  memcpy(relayippacket, packet, len); 
  memcpy(relayippacket, &eth, ETH_HLEN);
}

