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

struct interface {
  char ifname[IFNAMSIZ];
  struct in_addr ipaddr;
  struct in_addr bcast;
  struct in_addr netmask;
  struct in_addr network;
  unsigned char mac[ETH_ALEN];
};

typedef struct _arp_entry {
  struct in_addr ipaddr;
  unsigned char mac[ETH_ALEN];
} arp_entry;

int if_initialize(void);
void if_destroy(void);
char *if_error(void);
int if_send_spoof_request(const char *dev, unsigned int new_ip,
			  unsigned int r_ip, const unsigned char *rm,
                          int count, int icmp);
int if_list_ips(struct interface *ifs, int size);
int if_down(struct interface *areq);
int if_up(struct interface *areq);
int sample_arp_cache(arp_entry **);
#endif
