#ifndef _MDNS_H
#define _MDNS_H

#include <zephyr/net/socket.h>

static const struct in6_addr mdns_addr = {
    {{0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB}}};

int mdns_socket_open_ipv6(const struct in6_addr *saddr, int timeout_msec);

int mdns_query_send(int sock, const char *name, size_t length);

size_t mdns_query_recv(int sock);

#endif
