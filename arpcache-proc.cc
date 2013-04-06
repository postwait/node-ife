/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#include "ife.h"
#include "ife-icmp-support.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>

static int arpcache_psize = 0;
static arp_entry *arpcache_private = NULL;

const unsigned char ff_ff_ff_ff_ff_ff[ETH_ALEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

int sample_arp_cache(arp_entry **l)
{
  char line[200];
  char ip[100];
  int  hw_type, flags;
  char hw_address[100];    /* MAC address */
  char mask[100];    
  char device[100];
  FILE *fp;
  int num,count=0;
  int tmp_size;

  if(l) *l = NULL;
  /* read the arp cache entries from the kernel via /proc */
  if ((fp = fopen("/proc/net/arp", "r")) == NULL) {
    return -1;
  }

  /* start with the assumption that the old size is the new size */
  tmp_size = arpcache_psize;
		
  if (fgets(line, sizeof(line), fp) != (char *) NULL){ /* skip first line */
    strcpy(mask, "-");
    strcpy(device, "-");
		
    /* read cache entries line by line */
    for ( count=0; fgets(line, sizeof(line), fp);){
      unsigned int *h, hint[ETH_ALEN];
      num = sscanf(line, "%s 0x%x 0x%x %100s %100s %100s",
		 ip, &hw_type, &flags, hw_address, mask, device);
      if (num < 6)
        break;

      if( count+1 > tmp_size ){				
        if( tmp_size > 0 ){
	  tmp_size *= 2;
	  arpcache_private = (arp_entry *)realloc(arpcache_private,
				     sizeof(arp_entry)*(tmp_size+1));
        } else {
	  tmp_size = 2;
	  arpcache_private = (arp_entry *)malloc(sizeof(arp_entry)*(tmp_size+1));
        }
      }
      arpcache_private[count].ipaddr.s_addr = inet_addr( ip );
      h = hint;
      sscanf(hw_address, "%02x:%02x:%02x:%02x:%02x:%02x",
             h, h+1, h+2, h+3, h+4, h+5);
      memcpy(arpcache_private[count].mac, hint, ETH_ALEN);
      count++;
    }
  }
	
  if( count == 0 ){
    if(arpcache_private) free(arpcache_private);
    arpcache_psize = 0;
    arpcache_private = (arp_entry *)malloc(sizeof(arp_entry));
    arpcache_private[0].ipaddr.s_addr = 0;
  } else {
    arpcache_psize = count;
    arpcache_private[count].ipaddr.s_addr = 0;
  }
  fclose(fp);
  if(l) *l = arpcache_private;
  return count;
}
