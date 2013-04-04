/* Copyright (c) 1995, Theo Schlossnagle. All rights reserved. */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#ifndef IFE_ICMP_SUPPORT_H
#define IFE_ICMP_SUPPORT_H

#include <stdint.h>

void compose_ping(unsigned char *buf, const unsigned char *mymac,
                  const unsigned char *rmmac, uint32_t new_ip, uint32_t r_ip);

#endif
