/* Copyright (c) 2001-2005 OmniTI, Inc. All rights reserved */
/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#define HAVE_REMOTE /* needed for PCAP_OPENFLAG */
#include "config.h"
#include <Iphlpapi.h>
#include <mprapi.h>
#include "ife.h"
#include "ife-icmp-support.h"

#define ARPHRD_ETHER  1   /* Ethernet 10Mbps    */
#define ARPOP_REPLY 2   /* ARP reply      */

struct ether_header
{
  unsigned char ether_dhost[ETH_ALEN]; /* destination eth addr */
  unsigned char ether_shost[ETH_ALEN]; /* source ether addr  */
  unsigned short  ether_type;    /* packet type ID field */
};

struct arphdr
{
  unsigned short  ar_hrd;   /* format of hardware address */
  unsigned short  ar_pro;   /* format of protocol address */
  unsigned char ar_hln;   /* length of hardware address */
  unsigned char ar_pln;   /* length of protocol address */
  unsigned short  ar_op;    /* ARP opcode (command)   */
};


#define IFLISTSIZE 1024
static HANDLE mpr_config = NULL;

static const char *_if_errors[] = {
  "Win32 Error"
};

int if_initialize(void) {
  MprConfigServerConnect(NULL, &mpr_config);
  if (mpr_config) return 0;
  return -1;
}

static DWORD if_last_error = 0;
static char win32_if_error_string[1024];

char *if_error(void) {
  LPVOID lpMsgBuf;
  if (!FormatMessage( 
      FORMAT_MESSAGE_ALLOCATE_BUFFER | 
      FORMAT_MESSAGE_FROM_SYSTEM | 
      FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      if_last_error,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPTSTR) &lpMsgBuf,
      0,
      NULL ))
  {
    snprintf(win32_if_error_string, sizeof(win32_if_error_string)-1,
      "[0x%08x] Win32 Error", if_last_error);
  }

  snprintf(win32_if_error_string, sizeof(win32_if_error_string)-1,
    "[0x%08x] %s", if_last_error, (LPCTSTR)lpMsgBuf);

  LocalFree( lpMsgBuf );

  return win32_if_error_string;
}

typedef int (*foreach_ip_func)(void *context, IP_ADAPTER_INFO *adapter, IP_ADDR_STRING *ip, const char *friendly);

static int foreach_ip(void *context, foreach_ip_func func)
{
  PIP_ADAPTER_INFO pAdapterInfo = NULL;
  PIP_ADAPTER_INFO pAdapter = NULL;
  DWORD dwRetVal = 0;
  ULONG ulOutBufLen = 0;
  u_int8_t family;
  struct sockaddr_in addr;
  int addrlen;
  int size = 8;
  int done = 0;

  pAdapterInfo = (IP_ADAPTER_INFO *) malloc( size*sizeof(IP_ADAPTER_INFO) );
  ulOutBufLen = size*sizeof(IP_ADAPTER_INFO);

  if (GetAdaptersInfo( pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
    free (pAdapterInfo);
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc ( sizeof(ulOutBufLen) );
  }

  if ((dwRetVal = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
    pAdapter = pAdapterInfo;
    while (pAdapter && !done) {
      IP_ADDR_STRING *iplist;
      char friendly[IFNAMSIZ];

      lookup_friendly_name(pAdapter->AdapterName, friendly, IFNAMSIZ-1);
      done = func(context, pAdapter, NULL, friendly);

      for(iplist = &pAdapter->IpAddressList; !done && iplist; iplist = iplist->Next) {
        done = func(context, pAdapter, iplist, friendly);
      }
      pAdapter = pAdapter->Next;
    }
  }
  else {
    fprintf(stderr, "Call to GetAdaptersInfo failed.\n");
    if_last_error = dwRetVal;
  }

  free(pAdapterInfo);
  return done;
}

static int do_if_down(void *context, IP_ADAPTER_INFO *adapter, IP_ADDR_STRING *ip, const char *friendly)
{
  struct interface *areq = (struct interface*)context;

  if (ip) {
    struct sockaddr_in addr;
    int addrlen;
    DWORD ret;
        
    addrlen = sizeof(addr);
    if (0 == WSAStringToAddress(ip->IpAddress.String, AF_INET, NULL, (struct sockaddr*)&addr, &addrlen)) {

//fprintf(stderr, "compare %08x vs %08x (%s)\n", addr.sin_addr.s_addr, areq->ipaddr.s_addr, friendly);

      if (addr.sin_addr.s_addr == areq->ipaddr.s_addr) {

        ret = DeleteIPAddress(ip->Context);
        if_last_error = ret;

//        fprintf(stderr, "DeleteIPAddress returned %08x\n", ret);

        return ret == 0 ? 1 : -1;
      }
    }
  }
  return 0;
}


int if_down(struct interface *areq) {
  if (foreach_ip(areq, do_if_down) == 1) {
    return 0;
  }
  return -1;
}

static int do_if_up(void *context, IP_ADAPTER_INFO *adapter, IP_ADDR_STRING *ip, const char *friendly)
{
  struct interface *areq = (struct interface*)context;

  if (ip == NULL) {
    if (!strcmp(friendly, areq->ifname)) {

      /* found the interface */
      ULONG context, instance;
      DWORD ret;

      ret = AddIPAddress(areq->ipaddr.s_addr, areq->netmask.s_addr, adapter->Index, &context, &instance);
      if_last_error = ret;
//      fprintf(stderr, "AddIPAddress ip=%08x mask=%08x returned %08x\n", areq->ipaddr.s_addr, areq->netmask.s_addr, ret);

      return ret == 0 ? 1 : -1;
    }
  }
  return 0;
}

int if_up(struct interface *areq) {
  if (foreach_ip(areq, do_if_up) == 1) {
    return 0;
  }
  return -1;
}

struct get_my_mac {
  unsigned int new_ip;
  char *my_mac;
};

static int do_get_mac(void *context, IP_ADAPTER_INFO *adapter, IP_ADDR_STRING *ip, const char *friendly)
{
  struct get_my_mac *get_mac = (struct get_my_mac*)context;

  if (ip) {
    struct sockaddr_in addr;
    int addrlen;
    DWORD ret;
        
    addrlen = sizeof(addr);
    if (0 == WSAStringToAddress(ip->IpAddress.String, AF_INET, NULL, (struct sockaddr*)&addr, &addrlen)) {
      if (addr.sin_addr.s_addr == get_mac->new_ip) {
        memcpy(get_mac->my_mac, &adapter->Address, ETH_ALEN);
        return 1;
      }
    }
  }
  return 0;
}


int if_send_spoof_request(const char *dev, unsigned int new_ip, unsigned int r_ip,
                          const unsigned char *remote_mac, int count, int icmp) {
  pcap_t *pcap;
  pcap_if_t *alldevs, *ifp;
  char errbuf[PCAP_ERRBUF_SIZE+1];
  int retval = -1;
  unsigned char my_mac[ETH_ALEN];
  struct get_my_mac get_mac;

  if (-1 == pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf)) {
    fprintf(stderr, "Failed to enum devices: %s\n", errbuf);
    return -1;
  }

  /* find the mac that matches new_ip (ugh) */
  get_mac.new_ip = new_ip;
  get_mac.my_mac = my_mac; 
  foreach_ip(&get_mac, do_get_mac);

  /* find the pcap iface that matches our new_ip */
  for (ifp = alldevs; ifp; ifp = ifp->next) {
    pcap_addr_t *a;

    for (a = ifp->addresses; a; a = a->next) {
      if (a->addr->sa_family == AF_INET) {
        unsigned long pcap_ip = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
        unsigned long pcap_mask = ((struct sockaddr_in*)a->netmask)->sin_addr.s_addr;
        
        if ((pcap_ip & pcap_mask) == (new_ip & pcap_mask)) {

          pcap = pcap_open(ifp->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);

          if (pcap) {
              int i;
              unsigned char buffer[60];
              unsigned char bc_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
              struct ether_header *eth;
              struct arphdr *arp;
              unsigned char *cp, *dest_mac;

              memset(buffer, 0, sizeof(buffer));
              eth = (struct ether_header*)buffer;
              memcpy(eth->ether_shost, my_mac, sizeof(my_mac));
              memcpy(eth->ether_dhost, bc_mac, sizeof(bc_mac));
              eth->ether_type = htons(ETH_P_ARP);

              arp = (struct arphdr*)(eth + 1);
              arp->ar_hrd = htons(ARPHRD_ETHER);
              arp->ar_pro = htons(ETH_P_IP);
              arp->ar_hln = ETH_ALEN;
              arp->ar_pln = 4;
              arp->ar_op = htons(ARPOP_REPLY);

              cp = (unsigned char*)(arp + 1);
              memcpy(cp, my_mac, sizeof(my_mac)); cp += ETH_ALEN;
              memcpy(cp, &new_ip, 4); cp += 4;
              dest_mac = cp;
              memcpy(cp, bc_mac, sizeof(bc_mac)); cp += ETH_ALEN;
              memcpy(cp, &r_ip, 4); cp += 4;

              for (i = 0; i < count; i++) {
                pcap_sendpacket(pcap, buffer, 60);
              }

              if (remote_mac) {
                memcpy(dest_mac, remote_mac, ETH_ALEN);
                memcpy(eth->ether_dhost, remote_mac, ETH_ALEN);
                for (i = 0; i < count; i++) {
                  pcap_sendpacket(pcap, buffer, 60);
                }

                if (icmp) {
                  compose_ping(buffer, my_mac, remote_mac, new_ip, r_ip);
                  pcap_sendpacket(pcap, buffer, 42);
                }
              }

              pcap_close(pcap);

              retval = 0;
          } else {
            fprintf(stderr, "Failed to open '%s' for packet sending: %s\n", ifp->name, errbuf);
          }
          
          goto done;
        }
      }
    }
  }
done:
  pcap_freealldevs(alldevs);
  
  return retval;
}

static int hostid = 0;

int gethostid(void)
{
  return hostid;
}

static int lookup_friendly_name(char *guid_name, char *friendly_out, DWORD friendly_len)
{
  WCHAR wguid[64];
  DWORD ret;
  WCHAR fname[2048];

  /* convert guid to wide char */
  MultiByteToWideChar(CP_ACP, 0, guid_name, -1, wguid, sizeof(wguid)/sizeof(WCHAR));

  ret = MprConfigGetFriendlyName(mpr_config, wguid, fname, sizeof(fname));

  if (NO_ERROR == ret) {
    ret = WideCharToMultiByte(CP_ACP, 0, fname, -1, friendly_out, friendly_len, NULL, NULL);
    friendly_out[ret] = '\0';
    return 1;
  }

  return 0;
}

struct if_list_thingy {
  struct interface *ifs;
  int size;
  int count;
};

static int do_if_list(void *context, IP_ADAPTER_INFO *adapter, IP_ADDR_STRING *ip, const char *friendly)
{
  struct if_list_thingy *thingy = (struct if_list_thingy*)context;
  int count = thingy->count;
  struct interface *ifs = thingy->ifs;
  struct sockaddr_in addr;
  int addrlen;

  if (ip == NULL) return 0;
  if (thingy->count == thingy->size) return 1;

  memset(&ifs[count], 0, sizeof(struct interface));
  strcpy(ifs[count].ifname, friendly);
  memcpy(ifs[count].mac, &adapter->Address, ETH_ALEN);

#if 0
  {
    fprintf(stderr, "\n\tAdapter Name: \t[%d] %s\n", strlen(adapter->AdapterName), adapter->AdapterName);
    fprintf(stderr, "\tAdapter Desc: \t%s\n", adapter->Description);
    fprintf(stderr, "\tAdapter Addr: \t[%02x:%02x:%02x:%02x:%02x:%02x]\n",
        ifs[count].mac[0], ifs[count].mac[1], ifs[count].mac[2],
        ifs[count].mac[3], ifs[count].mac[4], ifs[count].mac[5]);
    fprintf(stderr, "\tIP Address: \t%s\n", iplist->IpAddress.String);
    fprintf(stderr, "\tIP Mask: \t%s\n", iplist->IpMask.String);

    fprintf(stderr, "\tFriendly: \t%s\n", friendly);
    fprintf(stderr, "\tContext: \t%08x\n", iplist->Context);
  }
#endif

  addrlen = sizeof(addr);
  if (0 == WSAStringToAddress(ip->IpAddress.String, AF_INET, NULL, (struct sockaddr*)&addr, &addrlen)) {
    ifs[count].ipaddr = addr.sin_addr;
    addrlen = sizeof(addr);
    if (0 == WSAStringToAddress(ip->IpMask.String, AF_INET, NULL, (struct sockaddr*)&addr, &addrlen)) {
      ifs[count].netmask = addr.sin_addr;
    }
    hostid = ((struct sockaddr_in*)&addr)->sin_addr.S_un.S_addr;
    
    thingy->count++;
  }
  return 0;
}

/* Build a list of interfaces/IP-addresses/MAC adresses this 
	machine currently has configured.
	ifs points to a buffer large enough to hold size entries */
int
if_list_ips(struct interface *ifs, int size) {
  struct if_list_thingy thingy;

  thingy.ifs = ifs;
  thingy.size = size;
  thingy.count = 0;

  strcpy(ifs[0].ifname, "loopback");
  ifs[0].ipaddr.S_un.S_addr = htonl(0x7f000001);
  ifs[0].bcast.S_un.S_addr = 0x0;
  ifs[0].netmask.S_un.S_addr = htonl(0xffffff00);
  ifs[0].network.S_un.S_addr = htonl(0x7f000000);
  memset(ifs[0].mac, 0, ETH_ALEN);
  thingy.count++;

  foreach_ip(&thingy, do_if_list);

  return thingy.count;
}
/* vim: se sw=2 ts=2 et: */
