#include "mdns.h"
#include <zephyr/logging/log.h>
#include <zephyr/posix/fcntl.h>

LOG_MODULE_DECLARE(cc1352_greybus, 4);

#define MDNS_PORT 5353
#define MDNS_UNICAST_RESPONSE 0x8000U
#define MDNS_MAX_SUBSTRINGS 64
#define MDNS_RESPONSE_BUFFER_SIZE 100
#define MDNS_PTR_NAME_SIZE 100

#define MDNS_POINTER_OFFSET(p, ofs) ((void *)((char *)(p) + (ptrdiff_t)(ofs)))
#define MDNS_POINTER_OFFSET_CONST(p, ofs)                                      \
  ((const void *)((const char *)(p) + (ptrdiff_t)(ofs)))
#define MDNS_POINTER_DIFF(a, b)                                                \
  ((size_t)((const char *)(a) - (const char *)(b)))
#define MDNS_INVALID_POS ((size_t)-1)

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

static bool join_multicast_group(const struct in6_addr *mcast_addr) {
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

static uint16_t mdns_ntohs(const void *data) {
  uint16_t aligned;

  memcpy(&aligned, data, sizeof(uint16_t));
  return ntohs(aligned);
}

static void *mdns_htons(void *data, uint16_t val) {
  val = htons(val);
  memcpy(data, &val, sizeof(uint16_t));
  return MDNS_POINTER_OFFSET(data, sizeof(uint16_t));
}

static int mdns_is_string_ref(uint8_t val) { return (0xC0 == (val & 0xC0)); }

static struct mdns_string_pair_t
mdns_get_next_substring(const void *rawdata, size_t size, size_t offset) {
  int recursion;
  size_t length;
  const uint8_t *buffer = (const uint8_t *)rawdata;
  struct mdns_string_pair_t pair = {MDNS_INVALID_POS, 0, 0};

  if (offset >= size)
    return pair;
  if (!buffer[offset]) {
    pair.offset = offset;
    return pair;
  }
  recursion = 0;
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

  length = (size_t)buffer[offset++];
  if (size < offset + length)
    return pair;

  pair.offset = offset;
  pair.length = length;

  return pair;
}

static int mdns_socket_setup_ipv6(int sock, const struct in6_addr *jaddr,
                                  int timeout_msec) {
  unsigned int reuseaddr = 1;
  struct timeval tv;

  tv.tv_usec = timeout_msec * 1000;

  if (!join_multicast_group(jaddr)) {
    LOG_ERR("Failed to join multicast group");
    return -1;
  }

  zsock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseaddr,
                   sizeof(reuseaddr));
  zsock_setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuseaddr,
                   sizeof(reuseaddr));
  zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

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

static size_t mdns_string_find(const char *str, size_t length, char c,
                               size_t offset) {
  const void *found;

  if (offset >= length)
    return MDNS_INVALID_POS;
  found = memchr(str + offset, c, length - offset);
  if (found)
    return (size_t)MDNS_POINTER_DIFF(found, str);
  return MDNS_INVALID_POS;
}

static size_t mdns_string_table_find(struct mdns_string_table_t *string_table,
                                     const void *buffer, size_t capacity,
                                     const char *str, size_t first_length,
                                     size_t total_length) {
  size_t istr, offset, dot_pos, current_length;

  if (!string_table)
    return MDNS_INVALID_POS;

  for (istr = 0; istr < string_table->count; ++istr) {
    if (string_table->offset[istr] >= capacity)
      continue;
    offset = 0;
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
      dot_pos = mdns_string_find(str, total_length, '.', offset);
      if (dot_pos == MDNS_INVALID_POS)
        dot_pos = total_length;
      current_length = dot_pos - offset;

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

static void mdns_string_table_add(struct mdns_string_table_t *string_table,
                                  size_t offset) {
  size_t table_capacity;

  if (!string_table)
    return;

  string_table->offset[string_table->next] = offset;

  table_capacity =
      sizeof(string_table->offset) / sizeof(string_table->offset[0]);
  if (++string_table->count > table_capacity)
    string_table->count = table_capacity;
  if (++string_table->next >= table_capacity)
    string_table->next = 0;
}

static void *mdns_string_make(void *buffer, size_t capacity, void *data,
                              const char *name, size_t length,
                              struct mdns_string_table_t *string_table) {
  size_t last_pos = 0;
  size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);
  size_t pos, sub_length, total_length, ref_offset;

  if (name[length - 1] == '.')
    --length;
  while (last_pos < length) {
    pos = mdns_string_find(name, length, '.', last_pos);
    sub_length = ((pos != MDNS_INVALID_POS) ? pos : length) - last_pos;
    total_length = length - last_pos;

    ref_offset = mdns_string_table_find(
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

static int mdns_multicast_send(int sock, const void *buffer, size_t size) {
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

static int mdns_multiquery_send(int sock, const struct mdns_query_t *query,
                                size_t count, void *buffer, size_t capacity,
                                uint16_t query_id) {
  socklen_t saddrlen;
  size_t iq, tosend;
  struct sockaddr_storage addr_storage;
  struct sockaddr *saddr;
  struct mdns_header_t *header;
  uint16_t rclass = MDNS_CLASS_IN;
  void *data;

  if (!count || (capacity < (sizeof(struct mdns_header_t) + (6 * count))))
    return -1;

  saddr = (struct sockaddr *)&addr_storage;
  saddrlen = sizeof(addr_storage);
  if (zsock_getsockname(sock, saddr, &saddrlen) == 0) {
    if ((saddr->sa_family == AF_INET) &&
        (ntohs(((struct sockaddr_in *)saddr)->sin_port) == MDNS_PORT))
      rclass &= ~MDNS_UNICAST_RESPONSE;
    else if ((saddr->sa_family == AF_INET6) &&
             (ntohs(((struct sockaddr_in6 *)saddr)->sin6_port) == MDNS_PORT))
      rclass &= ~MDNS_UNICAST_RESPONSE;
  }

  header = (struct mdns_header_t *)buffer;
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
  for (iq = 0; iq < count; ++iq) {
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

  tosend = MDNS_POINTER_DIFF(data, buffer);
  if (mdns_multicast_send(sock, buffer, (size_t)tosend))
    return -1;
  return query_id;
}

static int mdns_string_skip(const void *buffer, size_t size, size_t *offset) {
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

static struct mdns_string_t mdns_string_extract(const void *buffer, size_t size,
                                                size_t *offset, char *str,
                                                size_t capacity) {
  size_t to_copy;
  size_t cur = *offset;
  size_t end = MDNS_INVALID_POS;
  struct mdns_string_pair_t substr;
  struct mdns_string_t result;
  char *dst = str;
  unsigned int counter = 0;
  size_t remain = capacity;

  result.str = str;
  result.length = 0;

  do {
    substr = mdns_get_next_substring(buffer, size, cur);
    if ((substr.offset == MDNS_INVALID_POS) ||
        (counter++ > MDNS_MAX_SUBSTRINGS))
      return result;
    if (substr.ref && (end == MDNS_INVALID_POS))
      end = cur + 2;
    if (substr.length) {
      to_copy = (substr.length < remain) ? substr.length : remain;
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

static struct mdns_string_t
mdns_record_parse_ptr(const void *buffer, size_t size, size_t offset,
                      size_t length, char *strbuffer, size_t capacity) {
  struct mdns_string_t empty = {0, 0};
  // PTR record is just a string
  if ((size >= offset + length) && (length >= 2))
    return mdns_string_extract(buffer, size, &offset, strbuffer, capacity);
  return empty;
}

static bool mdns_answer_check(const void *buffer, size_t size, size_t *offset,
                              size_t records) {
  int ret;
  struct mdns_string_t namestr;
  size_t parsed = 0, i, record_length, record_offset;
  uint16_t length;
  char namebuffer[MDNS_PTR_NAME_SIZE];
  char expected[] = "zephyr._greybus._tcp.local\0";

  for (i = 0; i < records; ++i) {
    mdns_string_skip(buffer, size, offset);
    if (((*offset) + 10) > size)
      return false;
    const uint16_t *data =
        (const uint16_t *)MDNS_POINTER_OFFSET(buffer, *offset);

    // uint16_t rtype = mdns_ntohs(data++);
    // uint16_t rclass = mdns_ntohs(data++);
    // uint32_t ttl = mdns_ntohl(data);
    data += 4;
    length = mdns_ntohs(data++);

    *offset += 10;

    if (length <= (size - (*offset))) {
      record_length = length;
      record_offset = *offset;
      namestr =
          mdns_record_parse_ptr(buffer, size, record_offset, record_length,
                                namebuffer, sizeof(namebuffer));

      ret = memcmp(expected, namestr.str, strlen(expected));
      if (ret == 0) {
        return true;
      }
      ++parsed;
    }

    *offset += length;
  }
  return false;
}

static size_t mdns_query_recv_internal(int sock, struct in6_addr *addrptr) {
  int ret;
  size_t data_size, offset;
  uint16_t flags, questions, answer_rrs;
  struct sockaddr_in6 addr;
  char buffer[MDNS_RESPONSE_BUFFER_SIZE];
  struct sockaddr *saddr = (struct sockaddr *)&addr;
  socklen_t addrlen = sizeof(addr);

  memset(&addr, 0, sizeof(addr));

  ret = zsock_recvfrom(sock, buffer, sizeof(buffer), 0, saddr, &addrlen);
  if (ret <= 0) {
    goto early_exit;
  }

  data_size = (size_t)ret;
  const uint16_t *data = (const uint16_t *)buffer;

  // uint16_t query_id = mdns_ntohs(data++);
  data++;
  flags = mdns_ntohs(data++);
  questions = mdns_ntohs(data++);
  answer_rrs = mdns_ntohs(data++);
  // uint16_t authority_rrs = mdns_ntohs(data++);
  // uint16_t additional_rrs = mdns_ntohs(data++);
  data += 2;
  (void)sizeof(flags);

  // Skip questions part
  for (int i = 0; i < questions; ++i) {
    offset = MDNS_POINTER_DIFF(data, buffer);
    if (!mdns_string_skip(buffer, data_size, &offset)) {
      goto early_exit;
    }
    data = (const uint16_t *)MDNS_POINTER_OFFSET_CONST(buffer, offset);
    // Record type and class not used, skip
    // uint16_t rtype = mdns_ntohs(data++);
    // uint16_t rclass = mdns_ntohs(data++);
    data += 2;
  }

  offset = MDNS_POINTER_DIFF(data, buffer);
  if (mdns_answer_check(buffer, data_size, &offset, answer_rrs)) {
    net_ipaddr_copy(addrptr, &addr.sin6_addr);
    return 1;
  }

early_exit:
  return 0;
}

size_t mdns_query_recv(int sock, struct in6_addr *addr_list,
                       size_t addr_list_len) {
  int ret, total = 0;

  do {
    ret = mdns_query_recv_internal(sock, &addr_list[total]);
    total += ret;
  } while (ret && total < addr_list_len);

  return total;
}

int mdns_socket_open_ipv6(const struct in6_addr *jaddr, int timeout_msec) {
  int sock = (int)zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0)
    return -1;
  if (mdns_socket_setup_ipv6(sock, jaddr, timeout_msec)) {
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
