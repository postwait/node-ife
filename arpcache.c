/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

static int arpcache_psize = 0;
static arp_entry *arpcache_private = NULL;

const unsigned char ff_ff_ff_ff_ff_ff[ETH_ALEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

#if defined(HAVE_PROC_NET_ARP)
int sample_arp_cache()
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
      int i;
      num = sscanf(line, "%s 0x%x 0x%x %100s %100s %100s",
		 ip, &hw_type, &flags, hw_address, mask, device);
      if (num < 6)
        break;

      if( count+1 > tmp_size ){				
        if( tmp_size > 0 ){
	  tmp_size *= 2;
	  arpcache_private = realloc(arpcache_private,
				     sizeof(arp_entry)*(tmp_size+1));
        } else {
	  tmp_size = 2;
	  arpcache_private = malloc(sizeof(arp_entry)*(tmp_size+1));
        }
      }
      arpcache_private[count].ipaddr.s_addr = (address)inet_addr( ip );
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
    arpcache_private = malloc(sizeof(arp_entry));
    arpcache_private[0].ipaddr.s_addr = 0;
  } else {
    arpcache_psize = count;
    arpcache_private[count].ipaddr.s_addr = 0;
  }
  fclose(fp);
}
#elif defined(CTL_NET)
void sample_arp_cache() {
  size_t len = 0;
  int count = 0;
  struct rt_msghdr *rtm;
  struct sockaddr_inarp *sa;
  struct sockaddr_dl *sdl;
  char *arpdata, *cp;
  int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS,  RTF_LLINFO };
  sysctl(mib, 6, NULL, &len, NULL, 0);
  arpdata = malloc(len);
  sysctl(mib, 6, arpdata, &len, NULL, 0);
  for(cp = arpdata; cp < (arpdata+len); cp+=rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)cp;
    sa = (struct sockaddr_inarp *)(rtm+1);
    count++;
  }
  if((!arpcache_private) || (arpcache_psize != count)) {
    if(arpcache_private) free(arpcache_private);
    arpcache_private = malloc(sizeof(arp_entry)*(count+1));
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
  return count;
}
#elif defined(DL_UDERROR_IND)
#include <inet/mib2.h>
#include <sys/stream.h>
#include <stropts.h>
#include <sys/strstat.h>
#include <sys/tihdr.h>
int sample_arp_cache(arp_entry **l) {
  int s=-1, getcode, flags, count = 0;
  char buf[512], *dbuf = NULL;
  struct opthdr *req;
  struct strbuf ctlbuf, databuf;
  struct T_optmgmt_req *tor = (struct T_optmgmt_req *)buf;
  struct T_optmgmt_ack *toa = (struct T_optmgmt_ack *)buf;
  struct T_error_ack *tea = (struct T_error_ack *)buf;
  mib2_ipNetToMediaEntry_t *np;
  mib2_ip_t *ip = NULL;

  if(l) *l = NULL;
  if(!arpcache_private) {
    arpcache_psize = 2;
    arpcache_private = (arp_entry *)calloc(sizeof(*arpcache_private), arpcache_psize);
    arpcache_private[0].ipaddr.s_addr = 0;
  }
  if(s < 0) {
    if((s = open("/dev/arp", O_RDWR)) < 0) {
      return -1;
    }
    if(ioctl(s, I_PUSH, "tcp") ||
       ioctl(s, I_PUSH, "udp") ||
       ioctl(s, I_PUSH, "icmp") ) {
      close(s);
      s = -1;
      return -1;
    }
  }

  tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
  tor->OPT_offset = sizeof (struct T_optmgmt_req);
  tor->OPT_length = sizeof (struct opthdr);
  tor->MGMT_flags = T_CURRENT;

  req = (struct opthdr *)&tor[1];
  req->level = EXPER_IP_AND_ALL_IRES;
  req->name  = 0;
  req->len   = 1;

  ctlbuf.buf = (char *)buf;
  ctlbuf.len = tor->OPT_length + tor->OPT_offset;
  flags = 0;
  if (putmsg(s, &ctlbuf, (struct strbuf *)0, flags) == -1) {
    return -1;
  }

  req = (struct opthdr *)&toa[1];
  ctlbuf.maxlen = sizeof (buf);
  for (;;) {
    flags = 0;
    getcode = getmsg(s, &ctlbuf, (struct strbuf *)0, &flags);
    if (getcode == -1) return -1;
    if (getcode == 0 &&
        ctlbuf.len >= (int)sizeof (struct T_optmgmt_ack) &&
        toa->PRIM_type == T_OPTMGMT_ACK &&
        toa->MGMT_flags == T_SUCCESS &&
        req->len == 0)  {
      break; /* ?? */
    }
    if (ctlbuf.len >= (int)sizeof (struct T_error_ack) &&
        tea->PRIM_type == T_ERROR_ACK) {
      goto error;
    }
    if (getcode != MOREDATA ||
        ctlbuf.len < (int)sizeof (struct T_optmgmt_ack) ||
        toa->PRIM_type != T_OPTMGMT_ACK ||
        toa->MGMT_flags != T_SUCCESS) {
      goto error;
    }

    dbuf = (char *)malloc(req->len);
    if(dbuf == NULL) goto error;
    databuf.maxlen = req->len;
    databuf.buf    = (char *)dbuf;
    databuf.len    = 0;
    flags = 0;
    getcode = getmsg(s, (struct strbuf *)0, &databuf, &flags);
    if(getcode != 0) goto error;

    if(req->level == MIB2_IP && req->name == 0) {
      ip = (mib2_ip_t *)dbuf;
      fprintf(stderr, "ip->ipNetToMediaEntrySize -> %d\n", ip->ipNetToMediaEntrySize);
    }
    if(!ip || req->level != MIB2_IP || req->name != MIB2_IP_MEDIA) continue;
    for(np = (mib2_ipNetToMediaEntry_t *)dbuf;
        (char *)np < (char *)dbuf + databuf.len;
        np = (mib2_ipNetToMediaEntry_t *)((char *)np + ip->ipNetToMediaEntrySize)) {
      if(count >= arpcache_psize) {
        arpcache_psize <<= 1;
        arpcache_private = (arp_entry *)realloc(arpcache_private, sizeof(arp_entry)*(arpcache_psize+1));
      }
      if(np->ipNetToMediaPhysAddress.o_length == ETH_ALEN) {
        arpcache_private[count].ipaddr.s_addr = np->ipNetToMediaNetAddress;
        memcpy(arpcache_private[count].mac, np->ipNetToMediaPhysAddress.o_bytes, ETH_ALEN);
        count++;
      }
    }
    free(dbuf);
    dbuf = NULL;
  }
  if(l) *l = arpcache_private;
  return count;
 error:
  if(dbuf) free(dbuf);
  return -1;
}

#if 0
  req->dl_primitive = DL_UDERROR_IND;
  req->dl_dest_addr_length = 0x0c;
  req->dl_dest_addr_offset = 0x10;
  req->dl_src_addr_length = 0x80;
  req->dl_src_addr_offset = 0x104;
  buf.maxlen = 0;
  buf.len = sizeof(dl_data_ack_ind_t);
  buf.buf = (caddr_t)req;
  putmsg(s, &buf, NULL, 0);
  buf.maxlen = sizeof(buffer);
  buf.len = 0;
  buf.buf = (caddr_t)ack;
  while(1) {
    int data[7];

    buf.maxlen = sizeof(data);
    buf.len = 0;
    buf.buf = (caddr_t)data;
    if(getmsg(s, &buf, NULL, &flagsp) != MOREDATA)
      break;
    if(dbuffer)
      dbuffer = (char *)realloc(dbuffer, offset+data[6]);
    else
      dbuffer = (char *)malloc(offset+data[6]);
    buf.maxlen = data[6];
    buf.buf = (caddr_t)((char *)dbuffer + offset);
    if(getmsg(s, NULL, &buf, &flagsp))
      break;
    offset+=data[6];
  }
  if(dbuffer) {
    int r, count=0;
    for(r=0; r<offset/4; r++) { 
      unsigned int *b = (unsigned int *)dbuffer+r;
      unsigned char *h;
      struct in_addr a;
      if(b[0] == 0x8 && b[1] > 0x0 && b[1] < IFNAMSIZ) {
	char *ifname = (char *)(b+2);
	ifname[b[1]] = '\0';
        b += 2;
	b += IFNAMSIZ/sizeof(unsigned int);
	b += 4; /* something else here */
fprintf(stderr, "*b -> %d\n", *b);
	if(0 && *b != sizeof(ether_addr_t)) /* sizeof mac address */
	    continue;
	h = (unsigned char *)(b+1); 
fprintf(stderr, "b[11] -> %d\n", b[11]);
	if(b[11] != sizeof(struct in_addr)) /* sizeof ipv4 address */
            continue;
        a.s_addr = b[9];  /* the address */
      }
    }

    arpcache_private[count].ipaddr.s_addr = 0;
    free(dbuffer);
#endif
#else
int sample_arp_cache(arp_entry **l) {
  if(!arpcache_private) {
    arpcache_psize = 0;
    arpcache_private = malloc(sizeof(arp_entry));
    arpcache_private[0].ip = 0;
  }
  if(l) *l = arpcache_private;
  return 0;
}
#endif
