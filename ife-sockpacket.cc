/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#include "ife.h"
#include "ife-icmp-support.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>

static int _if_sock=-1;
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
  struct ifconf d;
  struct ifreq *ifr, *end, *cur, *temp;
  struct in_addr ipaddr;
  char buffer[128];
  
  /* temporary storage for getting broadcast address */
  temp= (struct ifreq *)buffer;
  
  d.ifc_len= 4096;
  d.ifc_buf= (char *)malloc (d.ifc_len);
  if(ioctl (_if_sock, SIOCGIFCONF, &d) == -1) {
    free(d.ifc_buf);
    return 0;
  }

  ifr=(struct ifreq *)d.ifc_req;
  end=(struct ifreq *)((char *) ifr + d.ifc_len);
  while((ifr<end) && (count<size)) {
    cur= ifr;
    ifr=(struct ifreq *)((char *)&ifr[1]);
    if(cur->ifr_addr.sa_family != AF_INET)
      continue;
    memcpy(&ipaddr, &(((struct sockaddr_in *)&cur->ifr_addr)->sin_addr),
	   sizeof(struct in_addr));
    memcpy(temp, cur, sizeof(struct ifreq));
    if(ioctl (_if_sock, SIOCGIFFLAGS, (char *) cur) < 0)
      continue;
    if((cur->ifr_flags & IFF_UP) && (cur->ifr_flags & IFF_BROADCAST)) {
      memcpy(&ifs[count].ipaddr, &ipaddr, sizeof(struct in_addr));
      if(ioctl(_if_sock, SIOCGIFBRDADDR, (char *)temp) != -1)
	memcpy(&ifs[count].bcast,
	       &(((struct sockaddr_in *)&temp->ifr_addr)->sin_addr),
	       sizeof(struct in_addr));
      if(ioctl(_if_sock, SIOCGIFNETMASK, (char *)temp) != -1)
	memcpy(&ifs[count].netmask,
	       &(((struct sockaddr_in *)&temp->ifr_addr)->sin_addr),
	       sizeof(struct in_addr));
      strncpy(ifs[count].ifname, cur->ifr_ifrn.ifrn_name, IFNAMSIZ);
      count++;
    }
  }
  free(d.ifc_buf);
  return count;
}

int
if_down(struct interface *areq) {
  int ic, i, iname, ipaddr, inamlen;
  struct ifreq ifr;
  struct interface ifs[1024];

  ic = if_list_ips(ifs, 1024);
  if(!areq->ifname[0] && !areq->ipaddr.s_addr) {
    _if_error = _if_error_illegalinterface;
    return -1;
  }
  inamlen = strlen(areq->ifname);
  for(i=0;i<1024;i++) {
    iname=ipaddr=0;
    if(!areq->ifname[0] ||
	(!strncmp(areq->ifname, ifs[i].ifname, inamlen) &&
	 (ifs[i].ifname[inamlen]==':' || ifs[i].ifname[inamlen]=='\0')))
      iname=1;
    if((areq->ipaddr.s_addr==0) ||
       (areq->ipaddr.s_addr==ifs[i].ipaddr.s_addr))
      ipaddr=1;
    if(iname && ipaddr) {
      strcpy(ifr.ifr_name, ifs[i].ifname);
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
    if(!memcmp(&ifs[i].ipaddr, &(areq->ipaddr), sizeof(struct in_addr))) {
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
          ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_addr.s_addr =
            areq->bcast.s_addr;
          ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_family = AF_INET;
          ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_port = 0;
	  if(ioctl( _if_sock, SIOCSIFBRDADDR, (char *)&ifr) != -1) {
            ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr =
              areq->netmask.s_addr;
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
  return -1;
}
