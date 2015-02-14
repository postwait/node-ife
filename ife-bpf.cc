/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "ife.h"
#include "ife-icmp-support.h"
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <sys/sockio.h>
#include <ifaddrs.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <arpa/inet.h>

#define IFLISTSIZE 1024

static int _if_sock=-1;
static int _if_sock6=-1;
static int _if_bpf=-1;
static char _if_error_none[] = "";
static char _if_error_exists[] = "IP alias exists";
static char _if_error_nosuchinterface[] = "No such interface";
static char *_if_error=_if_error_none;

int if_initialize() {
  int socket_type, v, n=0;
  char device[sizeof "/dev/bpf000"];
  socket_type = SOCK_RAW;
  if((_if_sock = socket (AF_INET, socket_type, 0)) == -1) {
    return -1;
  }
  if((_if_sock6 = socket (AF_INET6, socket_type, 0)) == -1) {
    return -1;
  }
  do {
    (void)snprintf(device, sizeof(device), "/dev/bpf%d", n++);
    _if_bpf = open(device, O_WRONLY);
  } while (_if_bpf < 0 && errno == EBUSY && n < 999);
  if(_if_bpf < 0) {
    return -1;
  }
  v = 32768;      
  (void) ioctl(_if_bpf, BIOCSBLEN, (caddr_t)&v);
  return 0;
}  
char *if_error() {
  return _if_error;
}
int
if_send_spoof_request(const char *dev,
		      unsigned int new_ip, unsigned int r_ip,
                      const unsigned char *remote_mac,
		      int count,int icmp) {
  int i,ic;
  struct ifreq ifr;
  struct ether_header *eth;
  struct arphdr *arp;
  struct interface ifs[1024];
  unsigned char *cp, *dest_mac;
  static unsigned char buffer[60];
  static unsigned char my_mac[ETH_ALEN];
  static unsigned char bc_mac[ETH_ALEN] =
                {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  memset(&ifr, sizeof(struct ifreq), 0);
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  if (ioctl(_if_bpf, BIOCSETIF, (caddr_t)&ifr) < 0) {
     return -1;
  }
  ic = if_list_ips(ifs, 1024);
  for(i=0; i<ic; i++) {
    if(!strncmp(ifs[i].ifname, ifr.ifr_name, strlen(ifr.ifr_name)) &&
	(ifs[i].mac[0] || ifs[i].mac[1] || ifs[i].mac[2] ||
	 ifs[i].mac[3] || ifs[i].mac[4] || ifs[i].mac[5]) ) {
      memcpy(my_mac, ifs[i].mac, ETH_ALEN);
      break;
    }
  }
  memset(buffer, 0, 60);
  eth = (struct ether_header *)buffer;
  memcpy(eth->ether_shost, my_mac, ETH_ALEN);
  memcpy(eth->ether_dhost, bc_mac, ETH_ALEN);
  eth->ether_type = htons(ETH_P_ARP);
  arp = (struct arphdr *)(eth+1);
  arp->ar_hrd = htons(ARPHRD_ETHER);
  arp->ar_pro = htons(ETH_P_IP);
  arp->ar_hln = ETH_ALEN;
  arp->ar_pln = 4;
  arp->ar_op  = htons(ARPOP_REPLY);
  cp = (unsigned char *)(arp+1);
  memcpy(cp, my_mac, ETH_ALEN); cp+=ETH_ALEN;
  memcpy(cp, &new_ip, 4); cp+=4;
  dest_mac = cp;
  memcpy(cp, bc_mac, ETH_ALEN); cp+=ETH_ALEN;
  memcpy(cp, &r_ip, 4); cp+=4;
  for(i=0;i<count;i++)
    write(_if_bpf, buffer, 60);
  if(remote_mac) {
    memcpy(dest_mac, remote_mac, ETH_ALEN);
    memcpy(eth->ether_dhost, remote_mac, ETH_ALEN);
    for(i=0;i<count;i++)
      write(_if_bpf, buffer, 60);
    if(icmp) {
      compose_ping(buffer, my_mac, remote_mac, new_ip, r_ip);
      write(_if_bpf, buffer, 42);
    }
  }
  return i;
}

#ifndef _SIZEOF_ADDR_IFREQ
#define _SIZEOF_ADDR_IFREQ(ifr)	((ifr).ifr_addr.sa_len + IFNAMSIZ)
#endif

/* Build a list of interfaces/IP-addresses/MAC adresses this 
	machine currently has configured.
	ifs points to a buffer large enough to hold size entries */
int
if_list_ips(struct interface *ifs,
	int size) {
  int count=0;
  struct ifaddrs *ifap, *ifa;
  memset(ifs, 0, size * (&ifs[1] - &ifs[0]));
  
  if(getifaddrs(&ifap)) return 0;
 
  for(ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) continue;

    /* Handle LL adresses (MAC adress) */
    if(ifa->ifa_addr->sa_family == AF_LINK) {
      struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
      if(sdl->sdl_alen != ETH_ALEN) continue;
      memset(&ifs[count], sizeof(struct interface), 0);
      strncpy(ifs[count].ifname, sdl->sdl_data, sdl->sdl_nlen);
      ifs[count].ifname[sdl->sdl_nlen] = '\0';
      memcpy(ifs[count].mac, sdl->sdl_data+sdl->sdl_nlen, ETH_ALEN);
      continue;
    }

    /* Not AF_INET or AF_LINK, then ignore it */
    if(ifa->ifa_addr->sa_family == AF_INET6) {
      if((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_BROADCAST)) {
        ifs[count].family = AF_INET6;
        memcpy(&ifs[count].ip6addr, &(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr),
  	           sizeof(struct in6_addr));
        memcpy(&ifs[count].netmask6, &(((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr),
  	           sizeof(struct in6_addr));
        strncpy(ifs[count].ifname, ifa->ifa_name, IFNAMSIZ);
        count++;
        memcpy(&ifs[count], &ifs[count-1], sizeof(struct interface));
      }
    }
    else if(ifa->ifa_addr->sa_family == AF_INET) {
      if((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_BROADCAST)) {
        ifs[count].family = AF_INET;
        memcpy(&ifs[count].ipaddr, &(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr),
  	      sizeof(struct in_addr));
        memcpy(&ifs[count].netmask,
               &(((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr),
               sizeof(struct in_addr));
        ifs[count].bcast.s_addr = ifs[count].ipaddr.s_addr | ~ifs[count].netmask.s_addr;
        strncpy(ifs[count].ifname, ifa->ifa_name, IFNAMSIZ);
        count++;
        memcpy(&ifs[count], &ifs[count-1], sizeof(struct interface));
      }
    }
  }
  freeifaddrs(ifap);
  return count;
}

int
if_down(struct interface *areq) {
  int i, ic;
  struct interface ifs[IFLISTSIZE];
 
  ic = if_list_ips(ifs, IFLISTSIZE);
  for(i=0; i<ic; i++) {
    if((areq->family == AF_INET &&
        !memcmp(&ifs[i].ipaddr, &(areq->ipaddr), sizeof(struct in_addr))) ||
       (areq->family == AF_INET6 &&
        !memcmp(&ifs[i].ip6addr, &(areq->ip6addr), sizeof(struct in6_addr)))) {
      areq = NULL;
      break;
    }
  }
  if(areq) return -1;
  areq = &ifs[i];
  if(areq->family == AF_INET) {
    struct sockaddr_in *a;
    struct ifaliasreq toup;
    memset(&toup, 0, sizeof(toup));
    memcpy(&toup.ifra_name, areq->ifname, IFNAMSIZ);
    a = ((struct sockaddr_in *)&toup.ifra_addr);
    a->sin_len = sizeof(struct sockaddr_in);
    a->sin_family = AF_INET;
    memcpy(&a->sin_addr.s_addr, &areq->ipaddr, sizeof(struct in_addr));
    a = ((struct sockaddr_in *)&toup.ifra_broadaddr);
    a->sin_len = sizeof(struct sockaddr_in);
    a->sin_family = AF_INET;
    memcpy(&a->sin_addr.s_addr, &areq->bcast, sizeof(struct in_addr));
    a = ((struct sockaddr_in *)&toup.ifra_mask);
    a->sin_len = sizeof(struct sockaddr_in);
    a->sin_family = AF_INET;
    memcpy(&a->sin_addr.s_addr, &areq->netmask, sizeof(struct in_addr));
  
    if(ioctl(_if_sock, SIOCDIFADDR, &toup) < 0) {
        _if_error = _if_error_nosuchinterface;
    } else {
      return 0;
    }
  }
  else if(areq->family == AF_INET6) {
    struct sockaddr_in6 *a;
    struct in6_aliasreq toup = {
      .ifra_flags = 0, 
      .ifra_lifetime = { 0, 0, 0xffffffff, 0xffffffff }
    };
    memcpy(&toup.ifra_name, areq->ifname, IFNAMSIZ);
    a = &toup.ifra_addr;
    a->sin6_len = sizeof(struct sockaddr_in6);
    a->sin6_family = AF_INET6;
    memcpy((void *)&a->sin6_addr, (void *)&areq->ip6addr, sizeof(struct in6_addr));
    a = &toup.ifra_prefixmask;
    a->sin6_len = sizeof(struct sockaddr_in6);
    a->sin6_family = AF_INET6;
    memcpy((void *)&a->sin6_addr, (void *)&areq->netmask6, sizeof(struct in6_addr));
    if(ioctl(_if_sock6, SIOCDIFADDR_IN6, &toup) < 0) {
      perror("AIFADDR");
    } else {
      return 0;
    }
  }
  return -1;
}

int
if_up(struct interface *areq) {
  int i, ic;
  struct interface ifs[IFLISTSIZE];
 
  ic = if_list_ips(ifs, IFLISTSIZE);
  for(i=0; i<ic; i++) {
    if((areq->family == AF_INET &&
        !memcmp(&ifs[i].ipaddr, &(areq->ipaddr), sizeof(struct in_addr))) ||
       (areq->family == AF_INET6 &&
        !memcmp(&ifs[i].ip6addr, &(areq->ip6addr), sizeof(struct in6_addr)))) {
      _if_error = _if_error_exists;
      return 1;
    }
  }

  if(areq->family == AF_INET) {
    struct sockaddr_in *a;
    struct ifaliasreq toup;
    memset(&toup, 0, sizeof(toup));
    memcpy(&toup.ifra_name, areq->ifname, IFNAMSIZ);
    a = ((struct sockaddr_in *)&toup.ifra_addr);
    a->sin_len = sizeof(struct sockaddr_in);
    a->sin_family = AF_INET;
    memcpy(&a->sin_addr.s_addr, &areq->ipaddr.s_addr, sizeof(struct in_addr));
    a = ((struct sockaddr_in *)&toup.ifra_broadaddr);
    a->sin_len = sizeof(struct sockaddr_in);
    a->sin_family = AF_INET;
    memcpy(&a->sin_addr.s_addr, &areq->bcast.s_addr, sizeof(struct in_addr));
    a = ((struct sockaddr_in *)&toup.ifra_mask);
    a->sin_len = sizeof(struct sockaddr_in);
    a->sin_family = AF_INET;
    /* VIFs on BSD use netmask 0xffffffff as opposed to something sane */
    /* memcpy(&a->sin_addr.s_addr, &areq->netmask.s_addr, sizeof(struct in_addr)); */
    memset(&a->sin_addr.s_addr, 0xff, 4);
    if(ioctl(_if_sock, SIOCAIFADDR, &toup) < 0) {
      perror("AIFADDR");
    } else {
      return 0;
    }
  }
  else if(areq->family == AF_INET6) {
    struct sockaddr_in6 *a;
    struct in6_aliasreq toup = {
      .ifra_flags = 0, 
      .ifra_lifetime = { 0, 0, 0xffffffff, 0xffffffff }
    };
    memcpy(&toup.ifra_name, areq->ifname, IFNAMSIZ);
    a = &toup.ifra_addr;
    a->sin6_len = sizeof(struct sockaddr_in6);
    a->sin6_family = AF_INET6;
    memcpy((void *)&a->sin6_addr, (void *)&areq->ip6addr, sizeof(struct in6_addr));
    a = &toup.ifra_prefixmask;
    a->sin6_len = sizeof(struct sockaddr_in6);
    a->sin6_family = AF_INET6;
    memcpy((void *)&a->sin6_addr, (void *)&areq->netmask6, sizeof(struct in6_addr));
    if(ioctl(_if_sock6, SIOCAIFADDR_IN6, &toup) < 0) {
      perror("AIFADDR");
    } else {
      return 0;
    }
  }
  else return -1;

  return -1;
}

