#include "mdns.h"
#include <strings.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/cbprintf.h>

#define UART_DEVICE_NODE DT_CHOSEN(zephyr_shell_uart)

static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
LOG_MODULE_REGISTER(cc1352_greybus, 4);

void print_addr(struct in6_addr *addr) {
  LOG_DBG("%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X", addr->s6_addr[0],
          addr->s6_addr[1], addr->s6_addr[2], addr->s6_addr[3],
          addr->s6_addr[4], addr->s6_addr[5], addr->s6_addr[6],
          addr->s6_addr[7], addr->s6_addr[8], addr->s6_addr[9],
          addr->s6_addr[10], addr->s6_addr[11], addr->s6_addr[12],
          addr->s6_addr[13], addr->s6_addr[14], addr->s6_addr[15]);
}

void main(void) {
  if (!device_is_ready(uart_dev)) {
    return;
  }

  struct in6_addr nodes[5];
  char query[] = "_greybus._tcp.local\0";
  int ret;

  int sock = mdns_socket_open_ipv6(&mdns_addr, 1000);
  if (sock < 0) {
    LOG_ERR("Failed to create socket");
    return;
  }
  LOG_DBG("Socket Created");

  while (1) {
    mdns_query_send(sock, query, strlen(query));
    LOG_DBG("Sent Request");
    ret = mdns_query_recv(sock, nodes, 5, query, strlen(query));
    LOG_DBG("Got %d devices", ret);

    if (ret > 0) {
      print_addr(&nodes[0]);
    }

    k_sleep(K_MSEC(10000));
  }
}
