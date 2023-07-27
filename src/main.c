#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/crc.h>
#include <zephyr/sys/ring_buffer.h>

#define UART_DEVICE_NODE DT_CHOSEN(zephyr_shell_uart)

#define HDLC_BUFFER_SIZE 140

#define ADDRESS_GREYBUS 0x01
#define ADDRESS_DBG 0x02
#define ADDRESS_MCUMGR 0x03

#define HDLC_FRAME 0x7E
#define HDLC_ESC 0x7D
#define HDLC_ESC_FRAME 0x5E
#define HDLC_ESC_ESC 0x5D

#define RX_BUF_SIZE 1024

static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);

static void uart_rx_work_handler(struct k_work *);

RING_BUF_DECLARE(uart_rx_ringbuf, RX_BUF_SIZE);
K_WORK_DEFINE(uart_rx_work, uart_rx_work_handler);
// LOG_MODULE_REGISTER(cc1352_greybus, 4);

struct hdlc_block {
  uint8_t address;
  uint8_t control;
  uint8_t length;
  uint8_t buffer[HDLC_BUFFER_SIZE];
};

static void uart_poll_out_crc(const struct device *dev, uint8_t byte,
                              uint16_t *crc) {
  *crc = crc16_ccitt(*crc, &byte, 1);
  if (byte == HDLC_FRAME || byte == HDLC_ESC) {
    uart_poll_out(dev, HDLC_ESC);
    byte ^= 0x20;
  }
  uart_poll_out(dev, byte);
}

static void block_out(const struct device *dev,
                      const struct hdlc_block *block) {
  uint16_t crc = 0xffff;

  uart_poll_out(dev, HDLC_FRAME);
  uart_poll_out_crc(dev, block->address, &crc);
  uart_poll_out_crc(dev, block->control, &crc);

  for (int i = 0; i < block->length; i++) {
    uart_poll_out_crc(dev, block->buffer[i], &crc);
  }

  uint16_t crc_calc = crc ^ 0xffff;
  uart_poll_out_crc(dev, crc_calc, &crc);
  uart_poll_out_crc(dev, crc_calc >> 8, &crc);
  uart_poll_out(dev, HDLC_FRAME);
}

static void uart_rx_input_byte(uint8_t byte) {
  if (byte == HDLC_FRAME) {
    if (wpan->rx_buffer_len) {
      wpan_process_frame(wpan);
    }
  } else if (byte == HDLC_ESC) {
    wpan->next_escaped = true;
  } else {
    if (wpan->next_escaped) {
      byte ^= 0x20;
      wpan->next_escaped = false;
    }
    wpan->crc = crc16_ccitt(wpan->crc, &byte, 1);
    wpan_save_byte(wpan, byte);
  }
}

static int uart_rx_consume_ringbuf() {
  uint8_t *data;
  size_t len, tmp;
  int ret;

  len = ring_buf_get_claim(&uart_rx_ringbuf, &data, RX_BUF_SIZE);
  if (len == 0) {
    return 0;
  }

  tmp = len;

  do {
    uart_rx_input_byte(*data++);
  } while (--tmp);

  ret = ring_buf_get_finish(&uart_rx_ringbuf, len);
  if (ret < 0) {
    // LOG_ERR("Cannot flush ring buffer (%d)", ret);
  }

  return -EAGAIN;
}

static void uart_rx_work_handler(struct k_work *work) {
  int ret = -EAGAIN;

  while (ret == -EAGAIN) {
    ret = uart_rx_consume_ringbuf();
  }
}

static void serial_callback(const struct device *dev, void *user_data) {
  uint8_t *buf;
  int ret;

  if (!uart_irq_update(uart_dev) && !uart_irq_rx_ready(uart_dev)) {
    return;
  }

  ret = ring_buf_put_claim(&uart_rx_ringbuf, &buf, RX_BUF_SIZE);
  if (ret <= 0) {
    // No space
    return;
  }

  ret = uart_fifo_read(dev, buf, ret);
  if (ret < 0) {
    // Something went wrong
    return;
  }

  ret = ring_buf_put_finish(&uart_rx_ringbuf, ret);
  if (ret < 0) {
    // Some error
    return;
  }

  k_work_submit(&uart_rx_work);
}

void main(void) {
  int ret;

  if (!device_is_ready(uart_dev)) {
    return;
  }

  ret = uart_irq_callback_user_data_set(uart_dev, serial_callback, NULL);
  if (ret < 0) {
    return;
  }

  uart_irq_rx_enable(uart_dev);

  k_sleep(K_FOREVER);
}
