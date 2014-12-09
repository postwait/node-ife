/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#ifndef _IFE_H_
#define _IFE_H_

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#ifndef ETH_UP_STATE
#define ETH_UP_STATE 1
#endif
#ifndef ETH_DOWN_STATE
#define ETH_DOWN_STATE 2
#endif
#ifndef ETH_ANY_STATE
#define ETH_ANY_STATE 3
#endif


struct interface {
  char ifname[IFNAMSIZ];
  union {
    struct in_addr _ip4addr;
    struct in6_addr _ip6addr;
  } _ipaddr;
  union {
    struct in_addr _bcast4;
    struct in6_addr _bcast6;
  } _bcast;
  union {
    struct in_addr _netmask4;
    struct in6_addr _netmask6;
  } _netmask;
  union {
    struct in_addr _network4;
    struct in6_addr _network6;
  } _network;
  unsigned char mac[ETH_ALEN];
  uint8_t family;
  int state;
};

typedef struct _arp_entry {
  union {
    struct in_addr _ip4addr;
  } _ipaddr;
  unsigned char mac[ETH_ALEN];
} arp_entry;

#define ipaddr _ipaddr._ip4addr
#define ip6addr _ipaddr._ip6addr
#define bcast _bcast._bcast4
#define bcast6 _bcast._bcast6
#define netmask _netmask._netmask4
#define netmask6 _netmask._netmask6
#define network _network._network4
#define network6 _network._network6

int if_initialize(void);
void if_destroy(void);
char *if_error(void);
int if_send_spoof_request(const char *dev, unsigned int new_ip,
			  unsigned int r_ip, const unsigned char *rm,
                          int count, int icmp);
int if_list_ips(struct interface *ifs, int size);
int if_list_ips(struct interface *ifs, int size, int state);
int if_down(struct interface *areq);
int if_up(struct interface *areq);
int sample_arp_cache(arp_entry **);

static inline int set_prefix_from_netmask6(struct in6_addr *addr) {
  uint8_t idx, *cp, len = 0;
  cp = (uint8_t *)addr;
  for(idx=0;idx<16;idx++) {
    switch(cp[idx]) {
      case 0xff: len+=8; break;
      case 0xfe: len+=7; break;
      case 0xfc: len+=5; break;
      case 0xf8: len+=5; break;
      case 0xf0: len+=4; break;
      case 0xe0: len+=3; break;
      case 0xc0: len+=2; break;
      case 0x80: len+=1; break;
      default: break;
    }
  }
  return len;
}
static inline void set_netmask6_from_prefix(struct in6_addr *addr, int len) {
  uint8_t *cp = (uint8_t *)addr;
  int m, idx;
  for(idx=0;idx<16;idx++) {
    m = len;
    if(m > 8) m = 8;
    switch(m) {
      case 8: cp[idx] = 0xff; break;
      case 7: cp[idx] = 0xfe; break;
      case 6: cp[idx] = 0xfc; break;
      case 5: cp[idx] = 0xf8; break;
      case 4: cp[idx] = 0xf0; break;
      case 3: cp[idx] = 0xe0; break;
      case 2: cp[idx] = 0xc0; break;
      case 1: cp[idx] = 0x80; break;
      case 0: cp[idx] = 0x00; break;
      default: break;
    }
    len -= 8;
    if(len < 0) len = 0;
  }
}
#endif
