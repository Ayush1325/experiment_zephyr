#include "mdns.h"
#include <zephyr/logging/log.h>
#include <zephyr/posix/fcntl.h>

LOG_MODULE_DECLARE(cc1352_greybus, 4);

#define MDNS_PORT 5353
#define MDNS_UNICAST_RESPONSE 0x8000U
#define MDNS_MAX_SUBSTRINGS 64
#define NI_MAXSERV 1

#define MDNS_POINTER_OFFSET(p, ofs) ((void *)((char *)(p) + (ptrdiff_t)(ofs)))
#define MDNS_POINTER_OFFSET_CONST(p, ofs)                                      \
  ((const void *)((const char *)(p) + (ptrdiff_t)(ofs)))
#define MDNS_POINTER_DIFF(a, b)                                                \
  ((size_t)((const char *)(a) - (const char *)(b)))
#define MDNS_INVALID_POS ((size_t)-1)
#define MDNS_STRING_FORMAT(s) (int)((s).length), s.str

enum mdns_record_type {
  MDNS_RECORDTYPE_IGNORE = 0,
  // Address
  MDNS_RECORDTYPE_A = 1,
  // Domain Name pointer
  MDNS_RECORDTYPE_PTR = 12,
  // Arbitrary text string
  MDNS_RECORDTYPE_TXT = 16,
  // IP6 Address [Thomson]
  MDNS_RECORDTYPE_AAAA = 28,
  // Server Selection [RFC2782]
  MDNS_RECORDTYPE_SRV = 33,
  // Any available records
  MDNS_RECORDTYPE_ANY = 255
};

enum mdns_class { MDNS_CLASS_IN = 1, MDNS_CLASS_ANY = 255 };

enum mdns_entry_type {
  MDNS_ENTRYTYPE_QUESTION = 0,
  MDNS_ENTRYTYPE_ANSWER = 1,
  MDNS_ENTRYTYPE_AUTHORITY = 2,
  MDNS_ENTRYTYPE_ADDITIONAL = 3
};

typedef enum mdns_entry_type mdns_entry_type_t;

struct mdns_string_t {
  const char *str;
  size_t length;
};

typedef enum mdns_record_type mdns_record_type_t;

struct mdns_query_t {
  mdns_record_type_t type;
  const char *name;
  size_t length;
};

struct mdns_string_pair_t {
  size_t offset;
  size_t length;
  int ref;
};

struct mdns_header_t {
  uint16_t query_id;
  uint16_t flags;
  uint16_t questions;
  uint16_t answer_rrs;
  uint16_t authority_rrs;
  uint16_t additional_rrs;
};

struct mdns_string_table_t {
  size_t offset[16];
  size_t count;
  size_t next;
};

static void mdns_socket_close(int sock) { zsock_close(sock); }

bool join_multicast_group(const struct in6_addr *mcast_addr) {
  struct net_if_mcast_addr *mcast;
  struct net_if *iface;

  iface = net_if_get_default();
  if (!iface) {
    LOG_ERR("Could not get the default interface\n");
    return false;
  }

  mcast = net_if_ipv6_maddr_add(iface, mcast_addr);
  if (!mcast) {
    LOG_ERR("Could not add multicast address to interface");
    return false;
  }

  net_if_ipv6_maddr_join(iface, mcast);
  return true;
}

static inline uint16_t mdns_ntohs(const void *data) {
  uint16_t aligned;
  memcpy(&aligned, data, sizeof(uint16_t));
  return ntohs(aligned);
}

static void *mdns_htons(void *data, uint16_t val) {
  val = htons(val);
  memcpy(data, &val, sizeof(uint16_t));
  return MDNS_POINTER_OFFSET(data, sizeof(uint16_t));
}

static inline int mdns_is_string_ref(uint8_t val) {
  return (0xC0 == (val & 0xC0));
}

static inline struct mdns_string_pair_t
mdns_get_next_substring(const void *rawdata, size_t size, size_t offset) {
  const uint8_t *buffer = (const uint8_t *)rawdata;
  struct mdns_string_pair_t pair = {MDNS_INVALID_POS, 0, 0};
  if (offset >= size)
    return pair;
  if (!buffer[offset]) {
    pair.offset = offset;
    return pair;
  }
  int recursion = 0;
  while (mdns_is_string_ref(buffer[offset])) {
    if (size < offset + 2)
      return pair;

    offset = mdns_ntohs(MDNS_POINTER_OFFSET(buffer, offset)) & 0x3fff;
    if (offset >= size)
      return pair;

    pair.ref = 1;
    if (++recursion > 16)
      return pair;
  }

  size_t length = (size_t)buffer[offset++];
  if (size < offset + length)
    return pair;

  pair.offset = offset;
  pair.length = length;

  return pair;
}

static inline int mdns_socket_setup_ipv6(int sock,
                                         const struct in6_addr *jaddr) {
  unsigned int reuseaddr = 1;

  if (!join_multicast_group(jaddr)) {
    LOG_ERR("Failed to join multicast group");
    return -1;
  }

  zsock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseaddr,
                   sizeof(reuseaddr));
  zsock_setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuseaddr,
                   sizeof(reuseaddr));

  struct sockaddr_in6 sock_addr;
  memset(&sock_addr, 0, sizeof(struct sockaddr_in6));
  sock_addr.sin6_family = AF_INET6;
  sock_addr.sin6_addr = in6addr_any;
  sock_addr.sin6_port = htons(MDNS_PORT);

  if (zsock_bind(sock, (struct sockaddr *)&sock_addr,
                 sizeof(struct sockaddr_in6)))
    return -1;

  const int flags = zsock_fcntl(sock, F_GETFL, 0);
  zsock_fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  return 0;
}

static inline size_t mdns_string_find(const char *str, size_t length, char c,
                                      size_t offset) {
  const void *found;
  if (offset >= length)
    return MDNS_INVALID_POS;
  found = memchr(str + offset, c, length - offset);
  if (found)
    return (size_t)MDNS_POINTER_DIFF(found, str);
  return MDNS_INVALID_POS;
}

static inline size_t
mdns_string_table_find(struct mdns_string_table_t *string_table,
                       const void *buffer, size_t capacity, const char *str,
                       size_t first_length, size_t total_length) {
  if (!string_table)
    return MDNS_INVALID_POS;

  for (size_t istr = 0; istr < string_table->count; ++istr) {
    if (string_table->offset[istr] >= capacity)
      continue;
    size_t offset = 0;
    struct mdns_string_pair_t sub_string =
        mdns_get_next_substring(buffer, capacity, string_table->offset[istr]);
    if (!sub_string.length || (sub_string.length != first_length))
      continue;
    if (memcmp(str, MDNS_POINTER_OFFSET(buffer, sub_string.offset),
               sub_string.length))
      continue;

    // Initial substring matches, now match all remaining substrings
    offset += first_length + 1;
    while (offset < total_length) {
      size_t dot_pos = mdns_string_find(str, total_length, '.', offset);
      if (dot_pos == MDNS_INVALID_POS)
        dot_pos = total_length;
      size_t current_length = dot_pos - offset;

      sub_string = mdns_get_next_substring(
          buffer, capacity, sub_string.offset + sub_string.length);
      if (!sub_string.length || (sub_string.length != current_length))
        break;
      if (memcmp(str + offset, MDNS_POINTER_OFFSET(buffer, sub_string.offset),
                 sub_string.length))
        break;

      offset = dot_pos + 1;
    }

    // Return reference offset if entire string matches
    if (offset >= total_length)
      return string_table->offset[istr];
  }

  return MDNS_INVALID_POS;
}

static void *mdns_string_make_ref(void *data, size_t capacity,
                                  size_t ref_offset) {
  if (capacity < 2)
    return 0;
  return mdns_htons(data, 0xC000 | (uint16_t)ref_offset);
}

static inline void
mdns_string_table_add(struct mdns_string_table_t *string_table, size_t offset) {
  if (!string_table)
    return;

  string_table->offset[string_table->next] = offset;

  size_t table_capacity =
      sizeof(string_table->offset) / sizeof(string_table->offset[0]);
  if (++string_table->count > table_capacity)
    string_table->count = table_capacity;
  if (++string_table->next >= table_capacity)
    string_table->next = 0;
}

static inline void *mdns_string_make(void *buffer, size_t capacity, void *data,
                                     const char *name, size_t length,
                                     struct mdns_string_table_t *string_table) {
  size_t last_pos = 0;
  size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);
  if (name[length - 1] == '.')
    --length;
  while (last_pos < length) {
    size_t pos = mdns_string_find(name, length, '.', last_pos);
    size_t sub_length = ((pos != MDNS_INVALID_POS) ? pos : length) - last_pos;
    size_t total_length = length - last_pos;

    size_t ref_offset = mdns_string_table_find(
        string_table, buffer, capacity,
        (char *)MDNS_POINTER_OFFSET(name, last_pos), sub_length, total_length);
    if (ref_offset != MDNS_INVALID_POS)
      return mdns_string_make_ref(data, remain, ref_offset);

    if (remain <= (sub_length + 1))
      return 0;

    *(unsigned char *)data = (unsigned char)sub_length;
    memcpy(MDNS_POINTER_OFFSET(data, 1), name + last_pos, sub_length);
    mdns_string_table_add(string_table, MDNS_POINTER_DIFF(data, buffer));

    data = MDNS_POINTER_OFFSET(data, sub_length + 1);
    last_pos = ((pos != MDNS_INVALID_POS) ? pos + 1 : length);
    remain = capacity - MDNS_POINTER_DIFF(data, buffer);
  }

  if (!remain)
    return 0;

  *(unsigned char *)data = 0;
  return MDNS_POINTER_OFFSET(data, 1);
}

static inline int mdns_multicast_send(int sock, const void *buffer,
                                      size_t size) {
  struct sockaddr_storage addr_storage;
  struct sockaddr_in addr;
  struct sockaddr_in6 addr6;
  struct sockaddr *saddr = (struct sockaddr *)&addr_storage;
  socklen_t saddrlen = sizeof(struct sockaddr_storage);
  if (zsock_getsockname(sock, saddr, &saddrlen))
    return -1;
  if (saddr->sa_family == AF_INET6) {
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr.s6_addr[0] = 0xFF;
    addr6.sin6_addr.s6_addr[1] = 0x02;
    addr6.sin6_addr.s6_addr[15] = 0xFB;
    addr6.sin6_port = htons((unsigned short)MDNS_PORT);
    saddr = (struct sockaddr *)&addr6;
    saddrlen = sizeof(addr6);
  } else {
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl((((uint32_t)224U) << 24U) | ((uint32_t)251U));
    addr.sin_port = htons((unsigned short)MDNS_PORT);
    saddr = (struct sockaddr *)&addr;
    saddrlen = sizeof(addr);
  }

  if (zsock_sendto(sock, (const char *)buffer, size, 0, saddr, saddrlen) < 0)
    return -1;
  return 0;
}



static inline int mdns_multiquery_send(int sock,
                                       const struct mdns_query_t *query,
                                       size_t count, void *buffer,
                                       size_t capacity, uint16_t query_id) {
  struct sockaddr_storage addr_storage;
  struct sockaddr *saddr;
  uint16_t rclass = MDNS_CLASS_IN;
  void *data;

  if (!count || (capacity < (sizeof(struct mdns_header_t) + (6 * count))))
    return -1;

  saddr = (struct sockaddr *)&addr_storage;
  socklen_t saddrlen = sizeof(addr_storage);
  if (zsock_getsockname(sock, saddr, &saddrlen) == 0) {
    if ((saddr->sa_family == AF_INET) &&
        (ntohs(((struct sockaddr_in *)saddr)->sin_port) == MDNS_PORT))
      rclass &= ~MDNS_UNICAST_RESPONSE;
    else if ((saddr->sa_family == AF_INET6) &&
             (ntohs(((struct sockaddr_in6 *)saddr)->sin6_port) == MDNS_PORT))
      rclass &= ~MDNS_UNICAST_RESPONSE;
  }

  struct mdns_header_t *header = (struct mdns_header_t *)buffer;
  // Query ID
  header->query_id = htons((unsigned short)query_id);
  // Flags
  header->flags = 0;
  // Questions
  header->questions = htons((unsigned short)count);
  // No answer, authority or additional RRs
  header->answer_rrs = 0;
  header->authority_rrs = 0;
  header->additional_rrs = 0;
  // Fill in questions
  data = MDNS_POINTER_OFFSET(buffer, sizeof(struct mdns_header_t));
  for (size_t iq = 0; iq < count; ++iq) {
    // Name string
    data = mdns_string_make(buffer, capacity, data, query[iq].name,
                            query[iq].length, 0);
    if (!data)
      return -1;
    // Record type
    data = mdns_htons(data, query[iq].type);
    //! Optional unicast response based on local port, class IN
    data = mdns_htons(data, rclass);
  }

  size_t tosend = MDNS_POINTER_DIFF(data, buffer);
  if (mdns_multicast_send(sock, buffer, (size_t)tosend))
    return -1;
  return query_id;
}

static uint32_t mdns_ntohl(const void *data) {
  uint32_t aligned;
  memcpy(&aligned, data, sizeof(uint32_t));
  return ntohl(aligned);
}

static inline int mdns_string_skip(const void *buffer, size_t size,
                                   size_t *offset) {
  size_t cur = *offset;
  struct mdns_string_pair_t substr;
  unsigned int counter = 0;
  do {
    substr = mdns_get_next_substring(buffer, size, cur);
    if ((substr.offset == MDNS_INVALID_POS) ||
        (counter++ > MDNS_MAX_SUBSTRINGS))
      return 0;
    if (substr.ref) {
      *offset = cur + 2;
      return 1;
    }
    cur = substr.offset + substr.length;
  } while (substr.length);

  *offset = cur + 1;
  return 1;
}

static struct mdns_string_t
ipv6_address_to_string(char *buffer, size_t capacity,
                       const struct sockaddr_in6 *addr, size_t addrlen) {
  char host[NI_MAXHOST] = {0};
  char service[NI_MAXSERV] = {0};
  int ret = getnameinfo((const struct sockaddr *)addr, (socklen_t)addrlen, host,
                        NI_MAXHOST, service, NI_MAXSERV,
                        NI_NUMERICSERV | NI_NUMERICHOST);
  int len = 0;
  if (ret == 0) {
    if (addr->sin6_port != 0)
      len = snprintf(buffer, capacity, "[%s]:%s", host, service);
    else
      len = snprintf(buffer, capacity, "%s", host);
  }
  if (len >= (int)capacity)
    len = (int)capacity - 1;
  struct mdns_string_t str;
  str.str = buffer;
  str.length = len;
  return str;
}

static struct mdns_string_t ip_address_to_string(char *buffer, size_t capacity,
                                                 const struct sockaddr *addr,
                                                 size_t addrlen) {
  return ipv6_address_to_string(buffer, capacity,
                                (const struct sockaddr_in6 *)addr, addrlen);
}

static inline struct mdns_string_t
mdns_string_extract(const void *buffer, size_t size, size_t *offset, char *str,
                    size_t capacity) {
  size_t cur = *offset;
  size_t end = MDNS_INVALID_POS;
  struct mdns_string_pair_t substr;
  struct mdns_string_t result;
  result.str = str;
  result.length = 0;
  char *dst = str;
  unsigned int counter = 0;
  size_t remain = capacity;
  do {
    substr = mdns_get_next_substring(buffer, size, cur);
    if ((substr.offset == MDNS_INVALID_POS) ||
        (counter++ > MDNS_MAX_SUBSTRINGS))
      return result;
    if (substr.ref && (end == MDNS_INVALID_POS))
      end = cur + 2;
    if (substr.length) {
      size_t to_copy = (substr.length < remain) ? substr.length : remain;
      memcpy(dst, (const char *)buffer + substr.offset, to_copy);
      dst += to_copy;
      remain -= to_copy;
      if (remain) {
        *dst++ = '.';
        --remain;
      }
    }
    cur = substr.offset + substr.length;
  } while (substr.length);

  if (end == MDNS_INVALID_POS)
    end = cur + 1;
  *offset = end;

  result.length = capacity - remain;
  return result;
}

static inline struct mdns_string_t
mdns_record_parse_ptr(const void *buffer, size_t size, size_t offset,
                      size_t length, char *strbuffer, size_t capacity) {
  // PTR record is just a string
  if ((size >= offset + length) && (length >= 2))
    return mdns_string_extract(buffer, size, &offset, strbuffer, capacity);
  struct mdns_string_t empty = {0, 0};
  return empty;
}

static inline size_t mdns_records_parse(int sock, const struct sockaddr *from,
                                        size_t addrlen, const void *buffer,
                                        size_t size, size_t *offset,
                                        mdns_entry_type_t type,
                                        uint16_t query_id, size_t records) {
  size_t parsed = 0;
  for (size_t i = 0; i < records; ++i) {
    size_t name_offset = *offset;
    mdns_string_skip(buffer, size, offset);
    if (((*offset) + 10) > size)
      return parsed;
    size_t name_length = (*offset) - name_offset;
    const uint16_t *data =
        (const uint16_t *)MDNS_POINTER_OFFSET(buffer, *offset);

    uint16_t rtype = mdns_ntohs(data++);
    uint16_t rclass = mdns_ntohs(data++);
    uint32_t ttl = mdns_ntohl(data);
    data += 2;
    uint16_t length = mdns_ntohs(data++);

    *offset += 10;

    if (length <= (size - (*offset))) {
      char addrbuffer[64];
      char namebuffer[256];
      char entrybuffer[256];
      size_t record_length = length;
      size_t record_offset = *offset;
      mdns_entry_type_t entry = type;
      struct mdns_string_t fromaddrstr =
          ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
      struct mdns_string_t namestr =
          mdns_record_parse_ptr(data, size, record_offset, record_length,
                                namebuffer, sizeof(namebuffer));
      const char *entrytype =
          (entry == MDNS_ENTRYTYPE_ANSWER)
              ? "answer"
              : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority"
                                                     : "additional");
      struct mdns_string_t entrystr = mdns_string_extract(
          data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
      LOG_DBG("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n",
              MDNS_STRING_FORMAT(fromaddrstr), entrytype,
              MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(namestr), rclass,
              ttl, (int)record_length);
      ++parsed;
    }

    *offset += length;
  }
  return parsed;
}

size_t mdns_query_recv(int sock) {
  struct sockaddr_in6 addr;
	char buffer[100];
  struct sockaddr *saddr = (struct sockaddr *)&addr;
  socklen_t addrlen = sizeof(addr);
  memset(&addr, 0, sizeof(addr));

  int ret = zsock_recvfrom(sock, buffer, sizeof(buffer), 0, saddr, &addrlen);
  if (ret <= 0) {
    LOG_ERR("Failed to recieve data %d", errno);
    return 0;
  }

  size_t data_size = (size_t)ret;
  const uint16_t *data = (const uint16_t *)buffer;

  uint16_t query_id = mdns_ntohs(data++);
  uint16_t flags = mdns_ntohs(data++);
  uint16_t questions = mdns_ntohs(data++);
  uint16_t answer_rrs = mdns_ntohs(data++);
  uint16_t authority_rrs = mdns_ntohs(data++);
  uint16_t additional_rrs = mdns_ntohs(data++);
  (void)sizeof(flags);

  // Skip questions part
  int i;
  for (i = 0; i < questions; ++i) {
    size_t offset = MDNS_POINTER_DIFF(data, buffer);
    if (!mdns_string_skip(buffer, data_size, &offset))
      return 0;
    data = (const uint16_t *)MDNS_POINTER_OFFSET_CONST(buffer, offset);
    // Record type and class not used, skip
    // uint16_t rtype = mdns_ntohs(data++);
    // uint16_t rclass = mdns_ntohs(data++);
    data += 2;
  }

  size_t records = 0;
  size_t total_records = 0;
  size_t offset = MDNS_POINTER_DIFF(data, buffer);
  records = mdns_records_parse(sock, saddr, addrlen, buffer, data_size, &offset,
                               MDNS_ENTRYTYPE_ANSWER, query_id, answer_rrs);
  total_records += records;
  LOG_DBG("Answer Records %d", records);
  if (records != answer_rrs)
    return total_records;

  records =
      mdns_records_parse(sock, saddr, addrlen, buffer, data_size, &offset,
                         MDNS_ENTRYTYPE_AUTHORITY, query_id, authority_rrs);
  total_records += records;
  LOG_DBG("Authority Records %d", records);
  if (records != authority_rrs)
    return total_records;

  records =
      mdns_records_parse(sock, saddr, addrlen, buffer, data_size, &offset,
                         MDNS_ENTRYTYPE_ADDITIONAL, query_id, additional_rrs);
  total_records += records;
  LOG_DBG("Additional Records %d", records);
  if (records != additional_rrs)
    return total_records;

  return total_records;
}

int mdns_socket_open_ipv6(const struct in6_addr *jaddr) {
  int sock = (int)zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0)
    return -1;
  if (mdns_socket_setup_ipv6(sock, jaddr)) {
    mdns_socket_close(sock);
    return -1;
  }
  return sock;
}

int mdns_query_send(int sock, const char *name, size_t length) {
  struct mdns_query_t query;
  char buffer[100];

  query.type = MDNS_RECORDTYPE_PTR;
  query.name = name;
  query.length = length;
  return mdns_multiquery_send(sock, &query, 1, buffer, sizeof(buffer), 0);
}
