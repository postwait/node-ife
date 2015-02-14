/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#include "ife.h"
#include "ife-icmp-support.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <ifaddrs.h>

struct in6_ifreq {
    struct in6_addr ifr6_addr;
    __u32 ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};

static int _if_sock=-1;
static int _if_sock6=-1;
static char _if_error_none[] = "";
static char _if_error_exists[] = "IP alias exists";
static char _if_error_noneleft[] = "To many VIPs";
static char _if_error_setip[] = "ioctl error setting IP address";
static char _if_error_setbroadcast[] = "ioctl error setting broadcast";
static char _if_error_setnetmask[] = "ioctl error setting netmask";
static char _if_error_setrunning[] = "ioctl error running|stopping interface";
static char _if_error_nosuchinterface[] = "No such interface";
static char _if_error_illegalinterface[] = "Illegal interface";
static char *_if_error=_if_error_none;

int if_initialize() {
  if((_if_sock = socket (AF_INET, SOCK_PACKET, htons(ETH_P_RARP))) == -1) {
    return -1;
  }
  if((_if_sock6 = socket (AF_INET6, SOCK_DGRAM, 0)) == -1) {
    return -1;
  }
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
  int i;
  struct ifreq ifr;
  struct sockaddr iface;
  struct ethhdr *eth;
  struct arphdr *arp;
  unsigned char *cp, *dest_mac;
  static unsigned char buffer[60];
  static unsigned char my_mac[ETH_ALEN];
  static unsigned char bc_mac[ETH_ALEN] =
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  strncpy(ifr.ifr_ifrn.ifrn_name, dev, IFNAMSIZ);
  if(ioctl(_if_sock, SIOCGIFHWADDR, &ifr) == -1) {
    return 0;
  }
  memcpy(my_mac, &((struct sockaddr *)&ifr.ifr_hwaddr)->sa_data, ETH_ALEN);
  memset(buffer, 0, 60);
  eth = (struct ethhdr *)buffer;
  memcpy(eth->h_source, my_mac, ETH_ALEN);
  memcpy(eth->h_dest, bc_mac, ETH_ALEN);
  eth->h_proto = htons(ETH_P_ARP);
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
  memset(&iface, 0, sizeof(struct sockaddr));
  strncpy(iface.sa_data, dev, sizeof(iface.sa_data));

  for(i=0;i<count;i++)
    sendto(_if_sock, buffer, 60, 0, (struct sockaddr *)&iface, sizeof(iface));

  if(remote_mac) {
    memcpy(dest_mac, remote_mac, ETH_ALEN);
    memcpy(eth->h_dest, remote_mac, ETH_ALEN);
    for(i=0;i<count;i++)
      sendto(_if_sock, buffer, 60, 0, (struct sockaddr *)&iface, sizeof(iface));
    if (icmp) {
      compose_ping(buffer, my_mac, remote_mac, new_ip, r_ip);
      sendto(_if_sock, buffer, 42, 0,
             (struct sockaddr *)&iface, sizeof(iface));
    }
  }
  return i;
}

int
if_list_ips(struct interface *ifs,
	int size) {
  int count=0;
  struct ifaddrs *ifap, *ifa;
  memset(ifs, 0, size * (&ifs[1] - &ifs[0]));
  
  if(getifaddrs(&ifap)) return 0;
 
  for(ifa = ifap; ifa; ifa = ifa->ifa_next) {
	/* Not AF_INET or AF_LINK, then ignore it */
    struct ifreq ifr;
    if(ifa->ifa_addr == NULL) continue;
    memset(&ifr, 0, sizeof(ifr));
    if(ifa->ifa_addr->sa_family == AF_INET6) {
      if((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_BROADCAST)) {
        ifs[count].family = AF_INET6;
        memcpy(&ifs[count].ip6addr, &(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr),
  	           sizeof(struct in6_addr));
        memcpy(&ifs[count].netmask6, &(((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr),
  	           sizeof(struct in6_addr));
        strncpy(ifs[count].ifname, ifa->ifa_name, IFNAMSIZ);
        strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ);
        if(ioctl(_if_sock, SIOCGIFHWADDR, &ifr) == 0 &&
           ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
          memcpy(ifs[count].mac, &ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
        }
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
        strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ);
        if(ioctl(_if_sock, SIOCGIFHWADDR, &ifr) == 0 &&
           ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
          memcpy(ifs[count].mac, &ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
        }
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
  int ic, i, iname, hasip, inamlen;
  struct ifreq ifr;
  struct interface ifs[1024];

  ic = if_list_ips(ifs, 1024);
  if(!areq->ifname[0] && !areq->ipaddr.s_addr) {
    _if_error = _if_error_illegalinterface;
    return -1;
  }
  inamlen = strlen(areq->ifname);
  for(i=0;i<1024;i++) {
    iname=hasip=0;
    if(!areq->ifname[0] ||
	(!strncmp(areq->ifname, ifs[i].ifname, inamlen) &&
	 (ifs[i].ifname[inamlen]==':' || ifs[i].ifname[inamlen]=='\0')))
      iname=1;
    if((areq->family == AF_INET &&
        (areq->ipaddr.s_addr==0 ||
         !memcmp(&ifs[i].ipaddr, &(areq->ipaddr), sizeof(struct in_addr))))) {
      hasip=1;
    }
    if((areq->family == AF_INET6 &&
        !memcmp(&ifs[i].ip6addr, &(areq->ip6addr), sizeof(struct in6_addr)))) {
      hasip = 1;
    }
    if(iname && hasip) {
      strcpy(ifr.ifr_name, ifs[i].ifname);
      if(areq->family == AF_INET) {
        if(ioctl(_if_sock, SIOCGIFFLAGS, (char *)&ifr) > -1) {
          ifr.ifr_flags &= ~(IFF_RUNNING | IFF_UP);
          if(ioctl(_if_sock, SIOCSIFFLAGS, (char *)&ifr) > -1) {
            _if_error=_if_error_none;
            memcpy(areq, &ifs[i], sizeof(struct interface));
            return 0;
          }
          _if_error = _if_error_setrunning;
          return -1;
        }
      }
      else if(areq->family == AF_INET6) {
        struct ifreq ifr;
        struct in6_ifreq ifr6;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifs[i].ifname, IFNAMSIZ);
        if (ioctl(_if_sock, SIOGIFINDEX, &ifr) < 0) {
          _if_error = _if_error_nosuchinterface;
          return -1;
        }
        memcpy((char *) &ifr6.ifr6_addr, (char *) &ifs[i].ip6addr,
    		       sizeof(struct in6_addr));
        ifr6.ifr6_ifindex = ifr.ifr_ifindex;
        ifr6.ifr6_prefixlen = set_prefix_from_netmask6(&ifs[i].netmask6);
        if (ioctl(_if_sock6, SIOCDIFADDR, &ifr6) < 0) {
          _if_error = _if_error_setrunning;
          return -1;
        }
        return 0;
      }
      else break;
    }
  }
  _if_error = _if_error_nosuchinterface;
  return -1;
}

int
if_up(struct interface *areq) {
  int i, ic, ifnamsiz;
  int vin[1024];
  struct ifreq ifr, ifq;
  struct interface ifs[1024];
  struct interface realreq;
  
  memcpy(&realreq, areq, sizeof(struct interface));
  realreq.ifname[0]='\0';
  vin[0]=-1; /* Linux screws up if you down ethx:0 */
  for(i=1;i<1024;i++) vin[i]=i;
  ic = if_list_ips(ifs, 1024);
  ifnamsiz = strlen(areq->ifname);
  for(i=0; i<ic; i++) {
    if((areq->family == AF_INET &&
        !memcmp(&ifs[i].ipaddr, &(areq->ipaddr), sizeof(struct in_addr))) ||
       (areq->family == AF_INET6 &&
        !memcmp(&ifs[i].ip6addr, &(areq->ip6addr), sizeof(struct in6_addr)))) {
      _if_error = _if_error_exists;
      return 1;
    }
    if(!strncmp(ifs[i].ifname, areq->ifname, ifnamsiz)) {
      if(ifs[i].ifname[ifnamsiz] == '\0') {
	snprintf(realreq.ifname, IFNAMSIZ, "%s:%d", areq->ifname, 0);
      } else {
	if(ifs[i].ifname[ifnamsiz] == ':') {
	  int tvin;
	  tvin = atoi(ifs[i].ifname + ifnamsiz + 1);
	  vin[tvin]=-1;
	}
      }
    }
  }
  if(realreq.ifname[0] == '\0') {
    /* Nobody is here */
    memcpy(realreq.ifname, areq->ifname, IFNAMSIZ);    
  } else {
    i=0;
    while(vin[i]==-1)
      i++;
    if(i>1023) {
      _if_error = _if_error_noneleft;
      return -i;
    }
    snprintf(realreq.ifname, IFNAMSIZ, "%s:%d", areq->ifname, vin[i]);    
    memcpy(areq->ifname, realreq.ifname, IFNAMSIZ);    
  }
  if(areq->family == AF_INET) {
    memcpy(ifr.ifr_name, realreq.ifname, IFNAMSIZ);
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr =
      areq->ipaddr.s_addr;
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_port = 0;
    
    if(ioctl( _if_sock, SIOCSIFADDR, (char *)&ifr) != -1) {
      memcpy(ifq.ifr_name, realreq.ifname, IFNAMSIZ);
      if(ioctl( _if_sock, SIOCGIFFLAGS, (char *)&ifq) != -1) {
        if(ifq.ifr_flags & IFF_RUNNING) {
          ifr.ifr_flags = ifq.ifr_flags | IFF_UP;
          if(ioctl( _if_sock, SIOCSIFFLAGS, (char *)&ifr) != -1) {
            ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_addr.s_addr = areq->bcast.s_addr;
            ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_family = AF_INET;
            ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_port = 0;
        	  if(ioctl( _if_sock, SIOCSIFBRDADDR, (char *)&ifr) != -1) {
              ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr = areq->netmask.s_addr;
              ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_family = AF_INET;
              ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_port = 0;
        	    if(ioctl( _if_sock, SIOCSIFNETMASK, (char *)&ifr) != -1) {
        	      ifr.ifr_flags = ifq.ifr_flags | IFF_BROADCAST;
                if(ioctl( _if_sock, SIOCSIFFLAGS, (char *)&ifr) != -1) {
                  return 0;
        	      }
              } else {
        	      _if_error = _if_error_setnetmask;
              }
            } else {
        	    _if_error = _if_error_setbroadcast;
            }
          } else {
            _if_error = _if_error_setrunning;
          }
        }
      }
    } else {
      _if_error = _if_error_setip;
    }
  }
  else if(areq->family == AF_INET6) {
    struct ifreq ifr;
    struct in6_ifreq ifr6;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, areq->ifname, IFNAMSIZ);
    if (ioctl(_if_sock, SIOGIFINDEX, &ifr) < 0) {
      _if_error = _if_error_nosuchinterface;
      return -1;
    }
    memcpy((char *) &ifr6.ifr6_addr, (char *) &areq->ip6addr,
		       sizeof(struct in6_addr));
    ifr6.ifr6_ifindex = ifr.ifr_ifindex;
    ifr6.ifr6_prefixlen = set_prefix_from_netmask6(&areq->netmask6);
    if (ioctl(_if_sock6, SIOCSIFADDR, &ifr6) < 0) {
      _if_error = _if_error_setip;
      return -1;
    }
    return 0;
  }
  return -1;
}
