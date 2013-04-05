#include "ife.h"

int sample_arp_cache(arp_entry **l) {
  if(!arpcache_private) {
    arpcache_psize = 0;
    arpcache_private = malloc(sizeof(arp_entry));
    arpcache_private[0].ip = 0;
  }
  if(l) *l = arpcache_private;
  return 0;
}
