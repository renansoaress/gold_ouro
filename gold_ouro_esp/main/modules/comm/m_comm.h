#ifndef COMM_H
#define COMM_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <errno.h>
#include <netdb.h> // struct addrinfo
#include <arpa/inet.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_sntp.h"
#include "esp_transport.h"
#include "esp_transport_tcp.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "nvs_flash.h"
#include "modules/utils/m_utils.h"
#include "modules/go/m_go.h"

esp_err_t send_data(char *msg, size_t len);

void init_communication(void);

#endif