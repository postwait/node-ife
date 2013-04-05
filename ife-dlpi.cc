/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#include "ife.h"
#include "ife-icmp-support.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/dlpi.h>
#include <unistd.h>
#include <stropts.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/ethernet.h>
#include <net/if_arp.h>

static int _if_sock=-1;
static int _if_dev=-1;
static char _if_error_none[] = "";
static char _if_error_exists[] = "IP alias exists";
static char _if_error_nosuchinterface[] = "No such interface";
static char _if_error_dlpi_error[] = "DLPI error";
static char _if_error_dlpi_unexpected[] = "DLPI unexpected response";
static char _if_error_alias_up_failed[] = "alias up failed";
static char _if_error_alias_down_failed[] = "alias down failed";
static char *_if_error=_if_error_none;

int if_initialize() {
  if(_if_sock >= 0) return -1;
  if((_if_sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    return -1;
  }
  _if_dev = -1;
  return 0;
}  
void if_destroy() {
  if(_if_sock >= 0) close(_if_sock);
  if(_if_dev >= 0) close(_if_dev);
  _if_sock = 0;
  _if_dev = 0;
}
char *if_error() {
  return _if_error;
}
static int
dlpi_attach(int fd, int instance) {
  dl_attach_req_t req;
  struct strbuf buf;

  req.dl_primitive = DL_ATTACH_REQ;
  req.dl_ppa = instance;
  buf.len = sizeof(req);
  buf.buf = (caddr_t) &req;
  return putmsg(fd, &buf, NULL, RS_HIPRI);
}
static int
dlpi_bind(int fd, u_long sap, u_long max_conind, u_long service_mode,
	  u_long conn_mgmt, u_long xidtest) {
  dl_bind_req_t br;
  struct strbuf ctl;

  br.dl_primitive = DL_BIND_REQ;
  br.dl_sap = sap;
  br.dl_max_conind = max_conind;
  br.dl_service_mode = service_mode;
  br.dl_conn_mgmt = conn_mgmt;
  br.dl_xidtest_flg = xidtest;
  ctl.maxlen = 0;
  ctl.len = sizeof(br);
  ctl.buf = (char *)&br;

  return putmsg(fd, &ctl, NULL, 0);
}
static int
dlpi_mac_req(int fd) {
  dl_phys_addr_req_t req;
  struct strbuf buf;

  req.dl_primitive = DL_PHYS_ADDR_REQ;
  req.dl_addr_type = DL_CURR_PHYS_ADDR;
  buf.len = sizeof(req);
  buf.buf = (caddr_t) &req;
  return putmsg(fd, &buf, NULL, RS_HIPRI);
}
static int
dlpi_get_reply(int fd, union DL_primitives *reply,
		int expected_prim, int maxlen) {
  struct strbuf buf;
  int flags, n;
  struct pollfd pfd;

  pfd.fd = fd;
  pfd.events = POLLIN | POLLPRI;
  do {
    n = poll(&pfd, 1, 1000);
  } while(n == -1 && errno == EINTR);
  if(n <= 0)
    return -1;
  buf.maxlen = maxlen;
  buf.buf = (caddr_t) reply;
  flags = 0;
  if(getmsg(fd, &buf, NULL, &flags) < 0) {
    return -1;
  }

  if(buf.len < (int)sizeof(ulong)) {
    _if_error = _if_error_dlpi_unexpected;
    return -1;
  }

  if(reply->dl_primitive == (unsigned int)expected_prim)
    return 0;

  if (reply->dl_primitive == DL_ERROR_ACK)
    _if_error = _if_error_dlpi_error;
  else
    _if_error = _if_error_dlpi_unexpected;
  return -1;
}

static int
dlpi_open_and_attach(char *dev) {
  int fd, instance;
  char ifdev[24];
  char *cp;
  struct {
    union DL_primitives prim;
    char space[64];
  } reply;

  strcpy(ifdev, "/dev/");
  cp = ifdev + 5;
  while(*dev != '\0')
    *cp++ = *dev++;
  *cp = '\0';
  cp--;
  while(*cp != '/' && isdigit((int)*cp)) *cp-- = '\0';
  instance = atoi(dev);
  fd = open(ifdev, O_RDWR);
  if(fd < 0) {
    _if_error = _if_error_nosuchinterface;
    return -1;
  }
  if(dlpi_attach(fd, instance) < 0) {
    close(fd);
    return -1;
  }
  if(dlpi_get_reply(fd, &reply.prim, DL_OK_ACK, sizeof(reply)) < 0) {
    close(fd);
    return -1;
  }
  if(dlpi_bind(fd, DL_ETHER, 0, DL_CLDLS, 0, 0) < 0) {
    close(fd);
    return -1;
  }
  if(dlpi_get_reply(fd, &reply.prim, DL_BIND_ACK, sizeof(reply)) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}
static int
if_get_mac_address(char *dev, char *mac) {
  int fd;
  struct {
    union DL_primitives prim;
    char space[64];
  } reply;

  if(_if_dev < 0)
    _if_dev = dlpi_open_and_attach(dev);

  if((fd = _if_dev) < 0) {
    return 0;
  }
  if(dlpi_mac_req(fd) < 0) {
    close(fd);
    return 0;
  }
  if(dlpi_get_reply(fd, &reply.prim,DL_PHYS_ADDR_ACK,sizeof(reply)) < 0) {
    close(fd);
    return 0;
  }
  if(reply.prim.physaddr_ack.dl_addr_length != ETH_ALEN) {
    _if_error = _if_error_dlpi_unexpected;
    close(fd);
  }
  memcpy(mac, (char *)&reply+reply.prim.physaddr_ack.dl_addr_offset, ETH_ALEN);
  return 1;
}

int
if_send_spoof_request(const char *dev,
		      unsigned int new_ip, unsigned int r_ip,
                      const unsigned char *remote_mac,
		      int count, int ping) {
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
  memcpy(&eth->ether_shost, my_mac, ETH_ALEN);
  memcpy(&eth->ether_dhost, bc_mac, ETH_ALEN);
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
  if(_if_dev < 0) {
    struct strioctl sioc;
    _if_dev = dlpi_open_and_attach((char *)dev);
    if(_if_dev < 0) {
      return 0;
    }
    sioc.ic_cmd = DLIOCRAW;
    sioc.ic_timout = -1;
    sioc.ic_len = 0;
    sioc.ic_dp = 0;
    if(ioctl(_if_dev, I_STR, &sioc) < 0) {
      close(_if_dev);
      _if_dev = -1;
    }
  }
  for(i=0;i<count;i++)
    write(_if_dev, buffer, 60);
  if(remote_mac) {
    memcpy(dest_mac, remote_mac, ETH_ALEN);
    memcpy(&eth->ether_dhost, remote_mac, ETH_ALEN);
    for(i=0;i<count;i++)
      write(_if_dev, buffer, 60);
    if(ping) {
      compose_ping(buffer, my_mac, remote_mac, new_ip, r_ip);
      write(_if_dev, buffer, 42);
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
  char buffer[1024];
  
  /* temporary storage for getting broadcast address */
  temp= (struct ifreq *)buffer;
 
  d.ifc_len= 4096*8;
  d.ifc_buf= (caddr_t) malloc (d.ifc_len);
  if(ioctl (_if_sock, SIOCGIFCONF, &d) == -1) {
    perror("ioctl (SIOCGIFCONF)");
    free(d.ifc_buf);
    return 0;
  }

  ifr=(struct ifreq *)(d.ifc_req);
  end=(struct ifreq *)(((char *) ifr) + d.ifc_len);
  while((ifr<end) && (count<size)) {
    cur= ifr;
    ifr = (struct ifreq *)(((char *)ifr)+sizeof(struct ifreq));
    if(((struct sockaddr_in *)&cur->ifr_addr)->sin_family != AF_INET)
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
      ifs[count].network.s_addr = ifs[count].ipaddr.s_addr & ifs[count].netmask.s_addr;
      strncpy(ifs[count].ifname, cur->ifr_name, IFNAMSIZ);
      memset(ifs[count].mac, 0, ETH_ALEN);
      if_get_mac_address(ifs[count].ifname, (char *)ifs[count].mac);
      count++;
    }
  }
  free(d.ifc_buf);
  return count;
}

int
if_down(struct interface *areq) {
  int i, ic, isvirtual = 0;
  struct interface ifs[1024];
 
  ic = if_list_ips(ifs, 1024);
  for(i=0; i<ic; i++) {
    if(!memcmp(&ifs[i].ipaddr, &(areq->ipaddr), sizeof(struct in_addr))) {
      areq = NULL;
      if(strchr(ifs[i].ifname, ':')) isvirtual=1;
      break;
    }
  }
  if(areq) return -1;
  areq = ifs + i;
#ifdef SIOCLIFREMOVEIF
  if(isvirtual) {
    struct lifreq todo;

    memset(&todo, 0, sizeof(todo));
    strncpy(todo.lifr_name, areq->ifname, IFNAMSIZ);
    ((struct sockaddr_in *)&todo.lifr_addr)->sin_family = AF_INET;
    memcpy(&((struct sockaddr_in *)&todo.lifr_addr)->sin_addr, &areq->ipaddr,
	   sizeof(struct in_addr));
    if(ioctl(_if_sock, SIOCLIFREMOVEIF, &todo) < 0) {
      return -1;
    }
    return 0;
  } else
#endif
  {
  /* Normal non-LIF code */
    struct ifreq todo;

    memset(&todo, 0, sizeof(todo));
    strncpy(todo.ifr_name, areq->ifname, IFNAMSIZ);
    ((struct sockaddr_in *)&todo.ifr_addr)->sin_family = AF_INET;
    memset(&((struct sockaddr_in *)&todo.ifr_addr)->sin_addr, 0,
	   sizeof(struct in_addr));
    ioctl(_if_sock, SIOCSIFADDR, &todo);
    memset(&todo, 0, sizeof(todo));
    strncpy(todo.ifr_name, areq->ifname, IFNAMSIZ);
    if(ioctl(_if_sock, SIOCGIFFLAGS, &todo) < 0) {
      _if_error = _if_error_alias_down_failed;
      return -1;
    }
    if(todo.ifr_flags & IFF_UP) {
      todo.ifr_flags &= ~IFF_UP;
      if(ioctl(_if_sock, SIOCSIFFLAGS, &todo) < 0) {
	_if_error = _if_error_alias_down_failed;
	return -1;
      }
    }
    if(!isvirtual) {
	/* FIXME: unplumb here */
    }
  }
  return 0;
}

int
if_up(struct interface *areq) {
  int i, ic, intexists=0;
  struct interface ifs[1024];
  ic = if_list_ips(ifs, 1024);
  for(i=0; i<ic; i++) {
    if(!memcmp(&ifs[i].ipaddr, &(areq->ipaddr), sizeof(struct in_addr))) {
      _if_error = _if_error_exists;
      return 1;
    }
    if(!strcmp(ifs[i].ifname, areq->ifname))
      intexists = 1;
  }
#ifdef SIOCLIFADDIF
  if(intexists) {
    /* Use LIFREQ */
    struct lifreq todo;
    char vdev[LIFNAMSIZ];
   
    memset(&todo, 0, sizeof(todo));
    strncpy(todo.lifr_name, areq->ifname, LIFNAMSIZ);
    ((struct sockaddr_in *)&todo.lifr_addr)->sin_family = AF_INET;
    memcpy(&((struct sockaddr_in *)&todo.lifr_addr)->sin_addr, &areq->ipaddr,
	   sizeof(struct in_addr));
    if(ioctl(_if_sock, SIOCLIFADDIF, &todo) < 0) {
      _if_error = _if_error_alias_up_failed;
      return -1;
    }
    strncpy(vdev, todo.lifr_name, LIFNAMSIZ);
    memset(&todo, 0, sizeof(todo));
    strncpy(todo.lifr_name, vdev, LIFNAMSIZ);
    ((struct sockaddr_in *)&todo.lifr_addr)->sin_family = AF_INET;
    memcpy(&((struct sockaddr_in *)&todo.lifr_addr)->sin_addr, &areq->netmask,
	   sizeof(struct in_addr));
    if(ioctl(_if_sock, SIOCSLIFNETMASK, &todo) < 0) {
      _if_error = _if_error_alias_up_failed;
      goto baillifremove;
    }
    memset(&todo, 0, sizeof(todo));
    strncpy(todo.lifr_name, vdev, LIFNAMSIZ);
    ((struct sockaddr_in *)&todo.lifr_addr)->sin_family = AF_INET;
    memcpy(&((struct sockaddr_in *)&todo.lifr_addr)->sin_addr, &areq->bcast,
	   sizeof(struct in_addr));
    if(ioctl(_if_sock, SIOCSLIFBRDADDR, &todo) < 0) {
      _if_error = _if_error_alias_up_failed;
      goto baillifremove;
    }
    memset(&todo, 0, sizeof(todo));
    strncpy(todo.lifr_name, vdev, LIFNAMSIZ);
    if(ioctl(_if_sock, SIOCGLIFFLAGS, &todo) < 0) {
      _if_error = _if_error_alias_up_failed;
      goto baillifremove;
    }
    if(!(todo.lifr_flags & IFF_UP)) {
      todo.lifr_flags |= IFF_UP;
      if(ioctl(_if_sock, SIOCSLIFFLAGS, &todo) < 0) {
	_if_error = _if_error_alias_up_failed;
	goto baillifremove;
      }
    }
    return 0;
 baillifremove:
    memset(&todo, 0, sizeof(todo));
    strncpy(todo.lifr_name, areq->ifname, IFNAMSIZ);
    ((struct sockaddr_in *)&todo.lifr_addr)->sin_family = AF_INET;
    memcpy(&((struct sockaddr_in *)&todo.lifr_addr)->sin_addr, &areq->ipaddr,
	   sizeof(struct in_addr));
    ioctl(_if_sock, SIOCLIFREMOVEIF, &todo);
  } else {
#endif
  /* old style */
    if(intexists) {
      /* We are not capable of LIFing, so we need to manually up an alias */
    } else {
      /* Main interface */
      struct ifreq todo;
      /* FIXME: we need to plumb here if necessary */

      memset(&todo, 0, sizeof(todo));
      strncpy(todo.ifr_name, areq->ifname, IFNAMSIZ);
      ((struct sockaddr_in *)&todo.ifr_addr)->sin_family = AF_INET;
      memcpy(&((struct sockaddr_in *)&todo.ifr_addr)->sin_addr, &areq->ipaddr,
	     sizeof(struct in_addr));
      if(ioctl(_if_sock, SIOCSIFADDR, &todo) < 0) {
        _if_error = _if_error_alias_up_failed;
        return -1;
      }
      memset(&todo, 0, sizeof(todo));
      strncpy(todo.ifr_name, areq->ifname, IFNAMSIZ);
      ((struct sockaddr_in *)&todo.ifr_addr)->sin_family = AF_INET;
      memcpy(&((struct sockaddr_in *)&todo.ifr_addr)->sin_addr, &areq->netmask,
	     sizeof(struct in_addr));
      if(ioctl(_if_sock, SIOCSIFNETMASK, &todo) < 0) {
        _if_error = _if_error_alias_up_failed;
        goto bailifremove;
      }
      memset(&todo, 0, sizeof(todo));
      strncpy(todo.ifr_name, areq->ifname, IFNAMSIZ);
      ((struct sockaddr_in *)&todo.ifr_addr)->sin_family = AF_INET;
      memcpy(&((struct sockaddr_in *)&todo.ifr_addr)->sin_addr, &areq->bcast,
	     sizeof(struct in_addr));
      if(ioctl(_if_sock, SIOCSIFBRDADDR, &todo) < 0) {
        _if_error = _if_error_alias_up_failed;
        goto bailifremove;
      }
      memset(&todo, 0, sizeof(todo));
      strncpy(todo.ifr_name, areq->ifname, IFNAMSIZ);
      if(ioctl(_if_sock, SIOCGIFFLAGS, &todo) < 0) {
        _if_error = _if_error_alias_up_failed;
        goto bailifremove;
      }
      if(!(todo.ifr_flags & IFF_UP)) {
        todo.ifr_flags |= IFF_UP;
        if(ioctl(_if_sock, SIOCSIFFLAGS, &todo) < 0) {
	  _if_error = _if_error_alias_up_failed;
	  goto bailifremove;
        }
      }
      return 0;
 bailifremove:
      memset(&todo, 0, sizeof(todo));
      strncpy(todo.ifr_name, areq->ifname, IFNAMSIZ);
      ((struct sockaddr_in *)&todo.ifr_addr)->sin_family = AF_INET;
      memset(&((struct sockaddr_in *)&todo.ifr_addr)->sin_addr, 0,
	     sizeof(struct in_addr));
      ioctl(_if_sock, SIOCSIFADDR, &todo);
    }
#ifdef SIOCLIFADDIF
  }
#endif
  return -1;
}

