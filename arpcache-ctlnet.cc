/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#include "ife.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/if_ether.h>

static int arpcache_psize = 0;
static arp_entry *arpcache_private = NULL;

const unsigned char ff_ff_ff_ff_ff_ff[ETH_ALEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

int sample_arp_cache(arp_entry **l) {
  size_t len = 0;
  int count = 0;
  struct rt_msghdr *rtm;
  struct sockaddr_inarp *sa;
  struct sockaddr_dl *sdl;
  char *arpdata, *cp;
  int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS,  RTF_LLINFO };

  if(l) *l = NULL;
  sysctl(mib, 6, NULL, &len, NULL, 0);
  arpdata = (char *)malloc(len);
  sysctl(mib, 6, arpdata, &len, NULL, 0);
  for(cp = arpdata; cp < (arpdata+len); cp+=rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)cp;
    sa = (struct sockaddr_inarp *)(rtm+1);
    count++;
  }
  if((!arpcache_private) || (arpcache_psize != count)) {
    if(arpcache_private) free(arpcache_private);
    arpcache_private = (arp_entry *)malloc(sizeof(arp_entry)*(count+1));
    arpcache_psize = count;
  }
  count = 0;
  for(cp = arpdata; cp < (arpdata+len); cp+=rtm->rtm_msglen) {
    unsigned char *h;
    rtm = (struct rt_msghdr *)cp;
    sa = (struct sockaddr_inarp *)(rtm+1);
    sdl = (struct sockaddr_dl *)(sa + 1);
    arpcache_private[count].ipaddr.s_addr = sa->sin_addr.s_addr;
    memcpy(arpcache_private[count].mac, ff_ff_ff_ff_ff_ff, ETH_ALEN);
    if(sdl->sdl_alen == ETH_ALEN) {
      memcpy(arpcache_private[count].mac, sdl->sdl_data+sdl->sdl_nlen, ETH_ALEN);
    }
    h = arpcache_private[count].mac;
    count++;
  }
  arpcache_private[count].ipaddr.s_addr = 0;
  free(arpdata);
  if(l) *l = arpcache_private;
  return count;
}
