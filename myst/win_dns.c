#include "common.h"
#include <Iphlpapi.h>
#define WIN_NS_9X            "System\\CurrentControlSet\\Services\\VxD\\MSTCP" 
#define WIN_NS_NT_KEY        "System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define WIN_DNSCLIENT        "Software\\Policies\\Microsoft\\System\\DNSClient"
#define WIN_NT_DNSCLIENT     "Software\\Policies\\Microsoft\\Windows NT\\DNSClient"
#define NAMESERVER           "NameServer"
#define DHCPNAMESERVER       "DhcpNameServer"
#define DATABASEPATH         "DatabasePath"
#define WIN_PATH_HOSTS       "\\hosts"
#define SEARCHLIST_KEY       "SearchList"
#define PRIMARYDNSSUFFIX_KEY "PrimaryDNSSuffix"
#define INTERFACES_KEY       "Interfaces"
#define DOMAIN_KEY           "Domain"
#define DHCPDOMAIN_KEY       "DhcpDomain"
typedef enum {
  WIN_UNKNOWN,
  WIN_3X,
  WIN_9X,
  WIN_NT,
  WIN_CE
} win_platform;

#define V_PLATFORM_WIN32s         0
#define V_PLATFORM_WIN32_WINDOWS  1
#define V_PLATFORM_WIN32_NT       2
#define V_PLATFORM_WIN32_CE       3

static win_platform __getplatform(void)
{
  OSVERSIONINFOEX OsvEx;

  memset(&OsvEx, 0, sizeof(OsvEx));
  OsvEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4996) /* warning C4996: 'GetVersionExW': was declared deprecated */
#endif
  if (!GetVersionEx((void *)&OsvEx))
  {
    memset(&OsvEx, 0, sizeof(OsvEx));
    OsvEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (!GetVersionEx((void *)&OsvEx))
      return WIN_UNKNOWN;
  }
#ifdef _MSC_VER
#pragma warning(pop)
#endif

  switch (OsvEx.dwPlatformId)
  {
  case V_PLATFORM_WIN32s:
    return WIN_3X;

  case V_PLATFORM_WIN32_WINDOWS:
    return WIN_9X;

  case V_PLATFORM_WIN32_NT:
    return WIN_NT;

  case V_PLATFORM_WIN32_CE:
    return WIN_CE;

  default:
    return WIN_UNKNOWN;
  }
}

typedef DWORD(WINAPI *fpGetNetworkParams_t) (FIXED_INFO*, DWORD*);
typedef ULONG (WINAPI *fpGetAdaptersAddresses_t) ( ULONG, ULONG, void*, IP_ADAPTER_ADDRESSES*, ULONG* );
typedef NETIO_STATUS (WINAPI *fpGetBestRoute2_t) ( NET_LUID *, NET_IFINDEX, const SOCKADDR_INET *, const SOCKADDR_INET *, ULONG, PMIB_IPFORWARD_ROW2, SOCKADDR_INET * );
static fpGetNetworkParams_t _fpGetNetworkParams;
static fpGetAdaptersAddresses_t _fpGetAdaptersAddresses;
static fpGetBestRoute2_t _fpGetBestRoute2;

struct ares_addr {
  int family;
  union {
    struct in_addr       addr4;
    struct in6_addr      addr6;
  } addr;
  int udp_port;  /* stored in network order */
  int tcp_port;  /* stored in network order */
};
#define addrV4 addr.addr4
#define addrV6 addr.addr6

static BOOL IsWindowsVistaOrGreater(void)
{
  OSVERSIONINFO vinfo;
  memset(&vinfo, 0, sizeof(vinfo));
  vinfo.dwOSVersionInfoSize = sizeof(vinfo);
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4996) /* warning C4996: 'GetVersionExW': was declared deprecated */
#endif
  if (!GetVersionEx(&vinfo) || vinfo.dwMajorVersion < 6)
    return FALSE;
  return TRUE;
#ifdef _MSC_VER
#pragma warning(pop)
#endif
}

/* A structure to hold the string form of IPv4 and IPv6 addresses so we can
 * sort them by a metric.
 */
typedef struct
{
  /* The metric we sort them by. */
  ULONG metric;

  /* Original index of the item, used as a secondary sort parameter to make
   * qsort() stable if the metrics are equal */
  size_t orig_idx;

  /* Room enough for the string form of any IPv4 or IPv6 address that
   * inet_ntop() will create.  Based on the existing c-ares practice.
   */
  char text[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
} Address;

/* Sort Address values \a left and \a right by metric, returning the usual
 * indicators for qsort().
 */
static int compareAddresses(const void *arg1,
  const void *arg2)
{
  const Address * const left = arg1;
  const Address * const right = arg2;
  /* Lower metric the more preferred */
  if(left->metric < right->metric) return -1;
  if(left->metric > right->metric) return 1;
  /* If metrics are equal, lower original index more preferred */
  if(left->orig_idx < right->orig_idx) return -1;
  if(left->orig_idx > right->orig_idx) return 1;
  return 0;
}
static void commanjoin(char** dst, const char* const src, const size_t len)
{
  char *newbuf;
  size_t newsize;

  /* 1 for terminating 0 and 2 for , and terminating 0 */
  newsize = len + (*dst ? (strlen(*dst) + 2) : 1);
  newbuf =realloc(*dst, newsize);
  if (!newbuf)
    return;
  if (*dst == NULL)
    *newbuf = '\0';
  *dst = newbuf;
  if (strlen(*dst) != 0)
    strcat(*dst, ",");
  strncat(*dst, src, len);
}

/*
 * commajoin()
 *
 * RTF code.
 */
static void commajoin(char **dst, const char *src)
{
  commanjoin(dst, src, strlen(src));
}

/*
 * get_DNS_NetworkParams()
 *
 * Locates DNS info using GetNetworkParams() function from the Internet
 * Protocol Helper (IP Helper) API. When located, this returns a pointer
 * in *outptr to a newly allocated memory area holding a null-terminated
 * string with a space or comma seperated list of DNS IP addresses.
 *
 * Returns 0 and nullifies *outptr upon inability to return DNSes string.
 *
 * Returns 1 and sets *outptr when returning a dynamically allocated string.
 *
 * Implementation supports Windows 98 and newer.
 *
 * Note: Ancient PSDK required in order to build a W98 target.
 */
static int get_DNS_NetworkParams(char **outptr)
{
  FIXED_INFO       *fi, *newfi;
  struct ares_addr namesrvr;
  char             *txtaddr;
  IP_ADDR_STRING   *ipAddr;
  int              res;
  DWORD            size = sizeof (*fi);

  *outptr = NULL;

  /* Verify run-time availability of GetNetworkParams() */
  if (_fpGetNetworkParams == NULL)
    return 0;

  fi = malloc(size);
  if (!fi)
    return 0;

  res = (*_fpGetNetworkParams) (fi, &size);
  if ((res != ERROR_BUFFER_OVERFLOW) && (res != ERROR_SUCCESS))
    goto done;

  newfi = realloc(fi, size);
  if (!newfi)
    goto done;

  fi = newfi;
  res = (*_fpGetNetworkParams) (fi, &size);
  if (res != ERROR_SUCCESS)
    goto done;

  for (ipAddr = &fi->DnsServerList; ipAddr; ipAddr = ipAddr->Next)
  {
    txtaddr = &ipAddr->IpAddress.String[0];

    /* Validate converting textual address to binary format. */
    if (inet_pton(AF_INET, txtaddr, &namesrvr.addrV4) == 1)
    {
      if ((namesrvr.addrV4.S_un.S_addr == INADDR_ANY) ||
        (namesrvr.addrV4.S_un.S_addr == INADDR_NONE))
        continue;
    }
    else if (inet_pton(AF_INET6, txtaddr, &namesrvr.addrV6) == 1)
    {
      if (memcmp(&namesrvr.addrV6, &in6addr_any,
          sizeof(namesrvr.addrV6)) == 0)
        continue;
    }
    else
      continue;

    commajoin(outptr, txtaddr);

    if (!*outptr)
      break;
  }

done:
  if (fi)
    free(fi);

  if (!*outptr)
    return 0;

  return 1;
}

/* There can be multiple routes to "the Internet".  And there can be different
 * DNS servers associated with each of the interfaces that offer those routes.
 * We have to assume that any DNS server can serve any request.  But, some DNS
 * servers may only respond if requested over their associated interface.  But
 * we also want to use "the preferred route to the Internet" whenever possible
 * (and not use DNS servers on a non-preferred route even by forcing request
 * to go out on the associated non-preferred interface).  i.e. We want to use
 * the DNS servers associated with the same interface that we would use to
 * make a general request to anything else.
 *
 * But, Windows won't sort the DNS servers by the metrics associated with the
 * routes and interfaces _even_ though it obviously sends IP packets based on
 * those same routes and metrics.  So, we must do it ourselves.
 *
 * So, we sort the DNS servers by the same metric values used to determine how
 * an outgoing IP packet will go, thus effectively using the DNS servers
 * associated with the interface that the DNS requests themselves will
 * travel.  This gives us optimal routing and avoids issues where DNS servers
 * won't respond to requests that don't arrive via some specific subnetwork
 * (and thus some specific interface).
 *
 * This function computes the metric we use to sort.  On the interface
 * identified by \a luid, it determines the best route to \a dest and combines
 * that route's metric with \a interfaceMetric to compute a metric for the
 * destination address on that interface.  This metric can be used as a weight
 * to sort the DNS server addresses associated with each interface (lower is
 * better).
 *
 * Note that by restricting the route search to the specific interface with
 * which the DNS servers are associated, this function asks the question "What
 * is the metric for sending IP packets to this DNS server?" which allows us
 * to sort the DNS servers correctly.
 */
static ULONG getBestRouteMetric(IF_LUID * const luid, /* Can't be const :( */
                                const SOCKADDR_INET * const dest,
                                const ULONG interfaceMetric)
{
  /* On this interface, get the best route to that destination. */
  MIB_IPFORWARD_ROW2 row;
  SOCKADDR_INET ignored;
  if(!_fpGetBestRoute2 ||
     _fpGetBestRoute2(/* The interface to use.  The index is ignored since we are
                           * passing a LUID.
                           */
                           luid, 0,
                           /* No specific source address. */
                           NULL,
                           /* Our destination address. */
                           dest,
                           /* No options. */
                           0,
                           /* The route row. */
                           &row,
                           /* The best source address, which we don't need. */
                           &ignored) != NO_ERROR
     /* If the metric is "unused" (-1) or too large for us to add the two
      * metrics, use the worst possible, thus sorting this last.
      */
     || row.Metric == (ULONG)-1
     || row.Metric > ((ULONG)-1) - interfaceMetric) {
    /* Return the worst possible metric. */
    return (ULONG)-1;
  }

  /* Return the metric value from that row, plus the interface metric.
   *
   * See
   * http://msdn.microsoft.com/en-us/library/windows/desktop/aa814494(v=vs.85).aspx
   * which describes the combination as a "sum".
   */
  return row.Metric + interfaceMetric;
}

/*
 * get_DNS_AdaptersAddresses()
 *
 * Locates DNS info using GetAdaptersAddresses() function from the Internet
 * Protocol Helper (IP Helper) API. When located, this returns a pointer
 * in *outptr to a newly allocated memory area holding a null-terminated
 * string with a space or comma seperated list of DNS IP addresses.
 *
 * Returns 0 and nullifies *outptr upon inability to return DNSes string.
 *
 * Returns 1 and sets *outptr when returning a dynamically allocated string.
 *
 * Implementation supports Windows XP and newer.
 */
#define IPAA_INITIAL_BUF_SZ 15 * 1024
#define IPAA_MAX_TRIES 3
static int get_DNS_AdaptersAddresses(char **outptr)
{
  IP_ADAPTER_DNS_SERVER_ADDRESS *ipaDNSAddr;
  IP_ADAPTER_ADDRESSES *ipaa, *newipaa, *ipaaEntry;
  ULONG ReqBufsz = IPAA_INITIAL_BUF_SZ;
  ULONG Bufsz = IPAA_INITIAL_BUF_SZ;
  ULONG AddrFlags = 0;
  int trying = IPAA_MAX_TRIES;
  int res;

  /* The capacity of addresses, in elements. */
  size_t addressesSize;
  /* The number of elements in addresses. */
  size_t addressesIndex = 0;
  /* The addresses we will sort. */
  Address *addresses;

  union {
    struct sockaddr     *sa;
    struct sockaddr_in  *sa4;
    struct sockaddr_in6 *sa6;
  } namesrvr;

  *outptr = NULL;

  /* Verify run-time availability of GetAdaptersAddresses() */
  if (_fpGetAdaptersAddresses == NULL)
    return 0;

  ipaa = malloc(Bufsz);
  if (!ipaa)
    return 0;

  /* Start with enough room for a few DNS server addresses and we'll grow it
   * as we encounter more.
   */
  addressesSize = 4;
  addresses = (Address*)malloc(sizeof(Address) * addressesSize);
  if(addresses == NULL) {
    /* We need room for at least some addresses to function. */
    free(ipaa);
    return 0;
  }

  /* Usually this call suceeds with initial buffer size */
  res = (*_fpGetAdaptersAddresses) (AF_UNSPEC, AddrFlags, NULL,
    ipaa, &ReqBufsz);
  if ((res != ERROR_BUFFER_OVERFLOW) && (res != ERROR_SUCCESS))
    goto done;

  while ((res == ERROR_BUFFER_OVERFLOW) && (--trying))
  {
    if (Bufsz < ReqBufsz)
    {
      newipaa = realloc(ipaa, ReqBufsz);
      if (!newipaa)
        goto done;
      Bufsz = ReqBufsz;
      ipaa = newipaa;
    }
    res = (*_fpGetAdaptersAddresses) (AF_UNSPEC, AddrFlags, NULL,
      ipaa, &ReqBufsz);
    if (res == ERROR_SUCCESS)
      break;
  }
  if (res != ERROR_SUCCESS)
    goto done;

  for (ipaaEntry = ipaa; ipaaEntry; ipaaEntry = ipaaEntry->Next)
  {
    if(ipaaEntry->OperStatus != IfOperStatusUp)
      continue;

    /* For each interface, find any associated DNS servers as IPv4 or IPv6
     * addresses.  For each found address, find the best route to that DNS
     * server address _on_ _that_ _interface_ (at this moment in time) and
     * compute the resulting total metric, just as Windows routing will do.
     * Then, sort all the addresses found by the metric.
     */
    for (ipaDNSAddr = ipaaEntry->FirstDnsServerAddress;
      ipaDNSAddr;
      ipaDNSAddr = ipaDNSAddr->Next)
    {
      namesrvr.sa = ipaDNSAddr->Address.lpSockaddr;

      if (namesrvr.sa->sa_family == AF_INET)
      {
        if ((namesrvr.sa4->sin_addr.S_un.S_addr == INADDR_ANY) ||
          (namesrvr.sa4->sin_addr.S_un.S_addr == INADDR_NONE))
          continue;

        /* Allocate room for another address, if necessary, else skip. */
        if(addressesIndex == addressesSize) {
          const size_t newSize = addressesSize + 4;
          Address * const newMem =
            (Address*)realloc(addresses, sizeof(Address) * newSize);
          if(newMem == NULL) {
            continue;
          }
          addresses = newMem;
          addressesSize = newSize;
        }

        /* Vista required for Luid or Ipv4Metric */
        if (IsWindowsVistaOrGreater())
        {
          /* Save the address as the next element in addresses. */
          addresses[addressesIndex].metric =
            getBestRouteMetric(&ipaaEntry->Luid,
              (SOCKADDR_INET*)(namesrvr.sa),
              ipaaEntry->Ipv4Metric);
        }
        else
        {
          addresses[addressesIndex].metric = (ULONG)-1;
        }

        /* Record insertion index to make qsort stable */
        addresses[addressesIndex].orig_idx = addressesIndex;

        if (! inet_ntop(AF_INET, &namesrvr.sa4->sin_addr,
            addresses[addressesIndex].text,
            sizeof(addresses[0].text))) {
          continue;
        }
        ++addressesIndex;
      }
      else if (namesrvr.sa->sa_family == AF_INET6)
      {
        if (memcmp(&namesrvr.sa6->sin6_addr, &in6addr_any,
            sizeof(namesrvr.sa6->sin6_addr)) == 0)
          continue;

        /* Allocate room for another address, if necessary, else skip. */
        if(addressesIndex == addressesSize) {
          const size_t newSize = addressesSize + 4;
          Address * const newMem =
            (Address*)realloc(addresses, sizeof(Address) * newSize);
          if(newMem == NULL) {
            continue;
          }
          addresses = newMem;
          addressesSize = newSize;
        }

        /* Vista required for Luid or Ipv4Metric */
        if (IsWindowsVistaOrGreater())
        {
          /* Save the address as the next element in addresses. */
          addresses[addressesIndex].metric =
            getBestRouteMetric(&ipaaEntry->Luid,
              (SOCKADDR_INET*)(namesrvr.sa),
              ipaaEntry->Ipv6Metric);
        }
        else
        {
          addresses[addressesIndex].metric = (ULONG)-1;
        }

        /* Record insertion index to make qsort stable */
        addresses[addressesIndex].orig_idx = addressesIndex;

        if (! inet_ntop(AF_INET6, &namesrvr.sa6->sin6_addr,
            addresses[addressesIndex].text,
            sizeof(addresses[0].text))) {
          continue;
        }
        ++addressesIndex;
      }
      else {
        /* Skip non-IPv4/IPv6 addresses completely. */
        continue;
      }
    }
  }

  /* Sort all of the textual addresses by their metric (and original index if
   * metrics are equal). */
  qsort(addresses, addressesIndex, sizeof(*addresses), compareAddresses);

  /* Join them all into a single string, removing duplicates. */
  {
    size_t i;
    for(i = 0; i < addressesIndex; ++i) {
      size_t j;
      /* Look for this address text appearing previously in the results. */
      for(j = 0; j < i; ++j) {
        if(strcmp(addresses[j].text, addresses[i].text) == 0) {
          break;
        }
      }
      /* Iff we didn't emit this address already, emit it now. */
      if(j == i) {
        /* Add that to outptr (if we can). */
        commajoin(outptr, addresses[i].text);
      }
    }
  }

done:
  free(addresses);

  if (ipaa)
    free(ipaa);

  if (!*outptr) {
    return 0;
  }

  return 1;
}
/*
 * get_enum_REG_SZ()
 *
 * Given a 'hKeyParent' handle to an open registry key and a 'leafKeyName'
 * pointer to the name of the registry leaf key to be queried, parent key
 * is enumerated searching in child keys for given leaf key name and its
 * associated string value. When located, this returns a pointer in *outptr
 * to a newly allocated memory area holding it as a null-terminated string.
 *
 * Returns 0 and nullifies *outptr upon inability to return a string value.
 *
 * Returns 1 and sets *outptr when returning a dynamically allocated string.
 *
 * Supported on Windows NT 3.5 and newer.
 */
static int get_enum_REG_SZ(HKEY hKeyParent, const char *leafKeyName,
                           char **outptr)
{
  char  enumKeyName[256];
  DWORD enumKeyNameBuffSize;
  DWORD enumKeyIdx = 0;
  HKEY  hKeyEnum;
  int   gotString;
  int   res;

  *outptr = NULL;

  for(;;)
  {
    enumKeyNameBuffSize = sizeof(enumKeyName);
    res = RegEnumKeyExA(hKeyParent, enumKeyIdx++, enumKeyName,
                       &enumKeyNameBuffSize, 0, NULL, NULL, NULL);
    if (res != ERROR_SUCCESS)
      break;
    res = RegOpenKeyExA(hKeyParent, enumKeyName, 0, KEY_QUERY_VALUE,
                       &hKeyEnum);
    if (res != ERROR_SUCCESS)
      continue;
    gotString = get_REG_SZ(hKeyEnum, leafKeyName, outptr);
    RegCloseKey(hKeyEnum);
    if (gotString)
      break;
  }

  if (!*outptr)
    return 0;

  return 1;
}

/*
 * get_DNS_Registry_NT()
 *
 * Functionally identical to get_DNS_Registry()
 *
 * Refs: Microsoft Knowledge Base articles KB120642 and KB314053.
 *
 * Implementation supports Windows NT 3.5 and newer.
 */
static int get_DNS_Registry_NT(char **outptr)
{
  HKEY hKey_Interfaces = NULL;
  HKEY hKey_Tcpip_Parameters;
  int  gotString;
  int  res;

  *outptr = NULL;

  res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, WIN_NS_NT_KEY, 0, KEY_READ,
    &hKey_Tcpip_Parameters);
  if (res != ERROR_SUCCESS)
    return 0;

  /*
   ** Global DNS settings override adapter specific parameters when both
   ** are set. Additionally static DNS settings override DHCP-configured
   ** parameters when both are set.
   */

  /* Global DNS static parameters */
  gotString = get_REG_SZ(hKey_Tcpip_Parameters, NAMESERVER, outptr);
  if (gotString)
    goto done;

  /* Global DNS DHCP-configured parameters */
  gotString = get_REG_SZ(hKey_Tcpip_Parameters, DHCPNAMESERVER, outptr);
  if (gotString)
    goto done;

  /* Try adapter specific parameters */
  res = RegOpenKeyExA(hKey_Tcpip_Parameters, "Interfaces", 0,
    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
    &hKey_Interfaces);
  if (res != ERROR_SUCCESS)
  {
    hKey_Interfaces = NULL;
    goto done;
  }

  /* Adapter specific DNS static parameters */
  gotString = get_enum_REG_SZ(hKey_Interfaces, NAMESERVER, outptr);
  if (gotString)
    goto done;

  /* Adapter specific DNS DHCP-configured parameters */
  gotString = get_enum_REG_SZ(hKey_Interfaces, DHCPNAMESERVER, outptr);

done:
  if (hKey_Interfaces)
    RegCloseKey(hKey_Interfaces);

  RegCloseKey(hKey_Tcpip_Parameters);

  if (!gotString || !*outptr)
    return 0;

  return 1;
}
/*
 * get_REG_SZ()
 *
 * Given a 'hKey' handle to an open registry key and a 'leafKeyName' pointer
 * to the name of the registry leaf key to be queried, fetch it's string
 * value and return a pointer in *outptr to a newly allocated memory area
 * holding it as a null-terminated string.
 *
 * Returns 0 and nullifies *outptr upon inability to return a string value.
 *
 * Returns 1 and sets *outptr when returning a dynamically allocated string.
 *
 * Supported on Windows NT 3.5 and newer.
 */
static int get_REG_SZ(HKEY hKey, const char *leafKeyName, char **outptr)
{
  DWORD size = 0;
  int   res;

  *outptr = NULL;

  /* Find out size of string stored in registry */
  res = RegQueryValueExA(hKey, leafKeyName, 0, NULL, NULL, &size);
  if ((res != ERROR_SUCCESS && res != ERROR_MORE_DATA) || !size)
    return 0;

  /* Allocate buffer of indicated size plus one given that string
     might have been stored without null termination */
  *outptr = malloc(size+1);
  if (!*outptr)
    return 0;

  /* Get the value for real */
  res = RegQueryValueExA(hKey, leafKeyName, 0, NULL,
                        (unsigned char *)*outptr, &size);
  if ((res != ERROR_SUCCESS) || (size == 1))
  {
    free(*outptr);
    *outptr = NULL;
    return 0;
  }

  /* Null terminate buffer allways */
  *(*outptr + size) = '\0';

  return 1;
}

/*
 * get_DNS_Registry_9X()
 *
 * Functionally identical to get_DNS_Registry()
 *
 * Implementation supports Windows 95, 98 and ME.
 */
static int get_DNS_Registry_9X(char **outptr)
{
  HKEY hKey_VxD_MStcp;
  int  gotString;
  int  res;

  *outptr = NULL;

  res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, WIN_NS_9X, 0, KEY_READ,
    &hKey_VxD_MStcp);
  if (res != ERROR_SUCCESS)
    return 0;

  gotString = get_REG_SZ(hKey_VxD_MStcp, NAMESERVER, outptr);
  RegCloseKey(hKey_VxD_MStcp);

  if (!gotString || !*outptr)
    return 0;

  return 1;
}

/*
 * get_DNS_Registry()
 *
 * Locates DNS info in the registry. When located, this returns a pointer
 * in *outptr to a newly allocated memory area holding a null-terminated
 * string with a space or comma seperated list of DNS IP addresses.
 *
 * Returns 0 and nullifies *outptr upon inability to return DNSes string.
 *
 * Returns 1 and sets *outptr when returning a dynamically allocated string.
 */
static int get_DNS_Registry(char **outptr)
{
  win_platform platform;
  int gotString = 0;

  *outptr = NULL;

  platform = __getplatform();

  if (platform == WIN_NT)
    gotString = get_DNS_Registry_NT(outptr);
  else if (platform == WIN_9X)
    gotString = get_DNS_Registry_9X(outptr);

  if (!gotString)
    return 0;

  return 1;
}

int get_DNS_Windows(char **outptr)
{
  static HMODULE hnd_iphlpapi = 0;
  if (!hnd_iphlpapi) {
    hnd_iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (!hnd_iphlpapi)
      return -1;

    _fpGetNetworkParams = (fpGetNetworkParams_t)
      GetProcAddress(hnd_iphlpapi, "GetNetworkParams");
    if (!_fpGetNetworkParams)
    {
      FreeLibrary(hnd_iphlpapi);
      return -1;
    }

    _fpGetAdaptersAddresses = (fpGetAdaptersAddresses_t)
      GetProcAddress(hnd_iphlpapi, "GetAdaptersAddresses");
    if (!_fpGetAdaptersAddresses)
    {
      /* This can happen on clients before WinXP, I don't
         think it should be an error, unless we don't want to
         support Windows 2000 anymore */
    }

    _fpGetBestRoute2 = (fpGetBestRoute2_t)
      GetProcAddress(hnd_iphlpapi, "GetBestRoute2");
    if (!_fpGetBestRoute2)
    {
      /* This can happen on clients before Vista, I don't
         think it should be an error, unless we don't want to
         support Windows XP anymore */
    }
  }

  /* Try using IP helper API GetAdaptersAddresses(). IPv4 + IPv6, also sorts
   * DNS servers by interface route metrics to try to use the best DNS server. */
  if (get_DNS_AdaptersAddresses(outptr))
    return 1;

  /* Try using IP helper API GetNetworkParams(). IPv4 only. */
  if (get_DNS_NetworkParams(outptr))
    return 1;

  /* Fall-back to registry information */
  return get_DNS_Registry(outptr);
}

