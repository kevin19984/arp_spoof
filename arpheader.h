#pragma once
#pragma pack(1)

struct arp_header {
  struct	arphdr ea_hdr;	/* fixed-size header */
  u_char	arp_sha[6];	/* sender hardware address */
  uint32_t	arp_spa;	/* sender protocol address */
  u_char	arp_tha[6];	/* target hardware address */
  uint32_t	arp_tpa;	/* target protocol address */
};

struct etherarp {
  struct ether_header eth;
  struct arp_header arp;
};

