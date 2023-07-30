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

void main(void) {
  if (!device_is_ready(uart_dev)) {
    return;
  }

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
    ret = mdns_query_recv(sock);
    LOG_DBG("Got %d devices", ret);
    k_sleep(K_MSEC(10000));
  }
}
