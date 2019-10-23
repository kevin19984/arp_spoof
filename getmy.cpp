#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include "getmy.h"

int getmymac (uint8_t *addr)
{
  struct ifreq ifr;
  struct ifreq *IFR;
  struct ifconf ifc;
  char buf[1024];
  int s, i;
  int ok = 0;
  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s==-1) {
    return -1;
  }
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  ioctl(s, SIOCGIFCONF, &ifc);
  IFR = ifc.ifc_req;
  for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; IFR++) {
    strcpy(ifr.ifr_name, IFR->ifr_name);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
      if (! (ifr.ifr_flags & IFF_LOOPBACK)) {
        if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
          ok = 1;
          break;
        }
      }
    }
  }
  close(s);
  if (ok) {
    bcopy( ifr.ifr_hwaddr.sa_data, addr, 6);
  }
  else {
    return -1;
  }
  return 0;
}

int getmyip (char* interface, uint32_t *addr)
{
  struct ifreq ifr;
  char ipstr[40];
  int s;
 
  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s==-1) {
    return -1;
  }
  strncpy(ifr.ifr_name, interface, IFNAMSIZ);
  if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
    return -1;
  } else {
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
    *addr = inet_addr((char*)ipstr);
  }
  return 0;
}
