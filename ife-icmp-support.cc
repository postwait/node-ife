/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#ifndef IFE_ICMP_CHECKSUM_H
#define IFE_ICMP_CHECKSUM_H

#include <stdint.h>
#include <string.h>

static int in_checksum(const unsigned short *buf, int len) {
  register long sum = 0;
  unsigned short answer = 0;
  while (len>1) { sum += *buf++; len -= 2; }
  if (len==1) {
    *(unsigned char*)(&answer) = *buf;
    sum += answer;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

void compose_ping(unsigned char *dpkt, const unsigned char *my_mac,
                  const unsigned char *remote_mac, uint32_t new_ip, uint32_t r_ip) {
  static unsigned char pkt[] =
    "\xff\xff\xff\xff\xff\xff"      /* ethernet destination */
    "\xff\xff\xff\xff\xff\xff"      /* ethernet source */
    "\x08\x00"                      /* ethernet type: 0x800, IP */
    "\x45\x00\x00\x1c"              /* ipv4, tos 0, length 28 */
    "\xfe\xfe\x00\x00"              /* id 0xfefe, may fragment */
    "\x40\x01\x00\x00"              /* ttl 64, ICMP, checksum 0 */
    "\x00\x00\x00\x00"              /* source ip */
    "\x00\x00\x00\x00"              /* destination ip */
    "\x08\x00\x00\x00"              /* icmp echo request, checksum 0 */
    "\xfe\xfe\xfe\xfe"              /* id 0xfefe, sequence number 0xfefe */
    ;
  /* Ethernet: 14, IP: 20, ICMP: 8 */
  memcpy(pkt,remote_mac,6);    /* ethernet destination and source addresses */
  memcpy(pkt+6,my_mac,6);    /* ethernet destination and source addresses */
  memcpy(pkt+14+12,&new_ip,4);
  memcpy(pkt+14+16,&r_ip,4);
  *(short*)(pkt+14+10)=0;           /* zero IP checksum */
  *(unsigned short*)(pkt+14+10)=in_checksum((unsigned short*)(pkt+14),20);
  *(short*)(pkt+14+20+2)=0;         /* zero ICMP checksum */
  *(unsigned short*)(pkt+14+20+2)=in_checksum((unsigned short*)(pkt+14+20),8);
  memcpy(dpkt,pkt,sizeof(pkt));
}

#endif
