/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at LICENSE-CDDL
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at LICENSE-CDDL.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 1995, Theo Schlossnagle. All rights reserved.
 * Copyright (c) 1990  Mentat Inc.
 */

#include "ife.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inet/mib2.h>
#include <sys/stream.h>
#include <stropts.h>
#include <sys/strstat.h>
#include <sys/tihdr.h>

static int arpcache_psize = 0;
static arp_entry *arpcache_private = NULL;

const unsigned char ff_ff_ff_ff_ff_ff[ETH_ALEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

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
       ioctl(s, I_PUSH, "icmp") )
      goto error;
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
  if (putmsg(s, &ctlbuf, (struct strbuf *)0, flags) == -1) goto error;

  req = (struct opthdr *)&toa[1];
  ctlbuf.maxlen = sizeof (buf);
  for (;;) {
    flags = 0;
    getcode = getmsg(s, &ctlbuf, (struct strbuf *)0, &flags);
    if (getcode == -1) goto error;
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
    }
    if(ip && req->level == MIB2_IP && req->name == MIB2_IP_MEDIA) {
      for(np = (mib2_ipNetToMediaEntry_t *)dbuf;
          (char *)np < (char *)dbuf + databuf.len;
          np = (mib2_ipNetToMediaEntry_t *)((char *)np + ip->ipNetToMediaEntrySize)) {
        if(ip->ipNetToMediaEntrySize == 0) break;
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
    }
    free(dbuf);
    dbuf = NULL;
  }
  if(l) *l = arpcache_private;
  close(s);
  return count;
 error:
  if(dbuf) free(dbuf);
  close(s);
  return -1;
}
