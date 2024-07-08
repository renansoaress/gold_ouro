#include "m_comm.h"

#define SNTP1 "a.st1.ntp.br"
#define SNTP2 "c.st1.ntp.br"
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define DNS_IP_BIT BIT2
#define SOCKET_GO_BIT BIT3
#define WIFI_SSID "SSID DA REDE"
#define WIFI_PASS "SENHA DA REDE"

static const char *TAG = "[GO - COMM]";
static bool CONNECTION_STATUS = false;
static EventGroupHandle_t my_event_group;
static TaskHandle_t wifi_status_task_handle = NULL;
static char host_ip[32] = "0.0.0.0";
static char host_dns[] = "my.pc";
static int tcp_sock = -1;
static esp_transport_handle_t transport_tcp = NULL;
static int count_msg = 0;
static char GOKEY[] = "minha senha secreta";

static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        xEventGroupSetBits(my_event_group, WIFI_FAIL_BIT);
        esp_wifi_connect();
        ESP_LOGI(TAG, "retry to connect to the AP");
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(my_event_group, WIFI_CONNECTED_BIT);
    }
}

static void dns_found_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    printf("Found dsn name: %s, %s\n", name, ipaddr_ntoa(ipaddr));
    strcpy(host_ip, ipaddr_ntoa(ipaddr));
    xEventGroupSetBits(my_event_group, DNS_IP_BIT);
}

static void time_sync_notification_cb(struct timeval *tv)
{
    ESP_LOGI(TAG, "Notification of a time synchronization event");
}

static esp_err_t config_sntp(void)
{
    esp_sntp_stop();
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, SNTP1);
    esp_sntp_setservername(1, SNTP2);
    sntp_set_time_sync_notification_cb(time_sync_notification_cb); // chama callback toda vez que sincroniza
    esp_sntp_init();
    int retry = 0;
    const int retry_count = 15;
    sntp_sync_status_t sntp_status = sntp_get_sync_status();
    while (
        sntp_status == SNTP_SYNC_STATUS_RESET && ++retry < retry_count)
    {
        ESP_LOGI(TAG, "Waiting get time... (%d/%d)-(%d)", retry, retry_count, sntp_status);
        // printf(" | sntp status: %d\n", sntp_status);
        vTaskDelay(3000 / portTICK_PERIOD_MS);
        sntp_status = sntp_get_sync_status();
    }
    // printf(" sntp status: %d\n", sntp_status);
    if (sntp_status != SNTP_SYNC_STATUS_COMPLETED)
    {
        return ESP_FAIL;
    }
    setenv("TZ", "GMT0", 1);
    // setenv("TZ", "BRT3BRST,M10.3.0/0,M2.3.0/0", 1);
    tzset();
    return ESP_OK;
}

static esp_err_t tcp_transport_stop_connect()
{
    if (transport_tcp != NULL)
    {
        esp_transport_close(transport_tcp);
        esp_transport_destroy(transport_tcp);
        transport_tcp = NULL;
        return ESP_OK;
    }
    return ESP_FAIL;
}

static esp_err_t tcp_transport_start_connect()
{
    int PORT = 4444;
    transport_tcp = esp_transport_tcp_init();
    if (transport_tcp == NULL)
    {
        ESP_LOGE(TAG, "Error occurred during esp_transport_proxy_init()");
        return ESP_FAIL;
    }

    in_addr_t ip = inet_addr(host_ip);
    if (IPADDR_ANY == ip)
    {
        int ret = dns_gethostbyname(host_dns, &ip, dns_found_cb, NULL);
        if (ret != 0)
        {
            if (xEventGroupWaitBits(my_event_group, DNS_IP_BIT, true, true, pdMS_TO_TICKS(5000)) != DNS_IP_BIT)
            {
                ESP_LOGE(TAG, "ERRO PARA OBTER O IP DO DNS!!!");
                return ESP_FAIL;
            }
        }
        printf("ip: %s [%d]\n", host_ip, ret);
    }
    else
    {
        printf("ip ok: %s\n", ipaddr_ntoa(&ip));
    }

    // esp_transport_keep_alive_t keep_alive_cfg = {
    //     .keep_alive_enable = 1,
    //     .keep_alive_count = 3,
    //     .keep_alive_idle = 3,     // sec
    //     .keep_alive_interval = 3, // sec
    // };
    // esp_transport_tcp_set_keep_alive(transport_tcp, &keep_alive_cfg);

    int err = esp_transport_connect(transport_tcp, host_ip, PORT, 10000);
    if (err != 0)
    {
        ESP_LOGE(TAG, "Client unable to connect: errno %d", errno);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Successfully connected");
    return ESP_OK;
}

static void wifi_status_task(void)
{
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(1000));
        EventBits_t bits = xEventGroupWaitBits(
            my_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT | SOCKET_GO_BIT,
            pdTRUE,
            pdFALSE,
            portMAX_DELAY);

        if (bits & WIFI_CONNECTED_BIT)
        {
            ESP_LOGI(TAG, "connected to ap SSID:%s password:%s",
                     WIFI_SSID, WIFI_PASS);
            esp_err_t ret = config_sntp();
            if (ret == ESP_FAIL)
            {
                esp_wifi_disconnect();
                continue;
            }

            xEventGroupSetBits(my_event_group, SOCKET_GO_BIT);
        }
        else if (bits & WIFI_FAIL_BIT)
        {
            tcp_transport_stop_connect();
        }
        else if (bits & SOCKET_GO_BIT)
        {
            tcp_transport_stop_connect();
            CONNECTION_STATUS = false;
            esp_err_t ret = ESP_FAIL;
            uint8_t retry_tcp_connection = 0;
            while (retry_tcp_connection < 3)
            {
                ESP_LOGI(TAG, "Conectando no socket (%d)!", retry_tcp_connection);
                ret = tcp_transport_start_connect();
                if (ret == ESP_OK)
                    break;
                retry_tcp_connection++;
                vTaskDelay(pdMS_TO_TICKS(5000));
            }

            if (ret == ESP_FAIL)
            {
                esp_wifi_disconnect();
            }
            else
            {
                CONNECTION_STATUS = true;
            }
        }
        else
        {
            ESP_LOGE(TAG, "UNEXPECTED EVENT");
            esp_restart();
        }
    }
    vTaskDelete(NULL);
}

static void wifi_init_sta(void)
{
    my_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    xTaskCreate(wifi_status_task, "status_wifi", 4096, NULL, 10, &wifi_status_task_handle);
}

esp_err_t send_data(char *msg, size_t len)
{
    if (!CONNECTION_STATUS)
    {
        ESP_LOGW(TAG, "Aguardando a conexão...");
        return ESP_ERR_NOT_FOUND;
    }

    int64_t iv_64 = generate_random_14_digit_number();
    // int64_t iv_64 = get_timestamp();
    // int64_t iv_64 = 999999999999999;
    char iv_hex[15] = {};
    sprintf(iv_hex, "%014llX", iv_64);
    printf("    *** IV: (%s) ***\n", iv_hex);

    char iv_go[23] = {0};
    sprintf(iv_go, "GOLD%sOURO", iv_hex);

    unsigned char *encrypted_msg = NULL;
    size_t encrypted_len = 0;

    encrypt_string(msg, GOKEY, iv_go, &encrypted_msg, &encrypted_len);
    // printf("Encrypt message[%d]: (%s)\n", encrypted_len, encrypted_msg);
    // printf("Encrypt message HEX: (");
    // for (int i = 0; i < encrypted_len; i++)
    // {
    //     printf("%02X", encrypted_msg[i]);
    // }
    // printf(")\n");

    // iv gold ouro
    char iv_ascii[8] = {0};
    int iv_ascii_len = 7;
    hex_to_ascii(iv_hex, iv_ascii);
    size_t new_msg_size = encrypted_len + 9;
    unsigned char new_msg[new_msg_size];
    new_msg[0] = 0x5E; // ^
    memcpy(new_msg + 1, iv_ascii, iv_ascii_len);
    memcpy(new_msg + 1 + iv_ascii_len, encrypted_msg, encrypted_len);
    new_msg[new_msg_size - 1] = 0x24; // $
    // printf("Encrypt new message[%d]: (%s)\n", new_msg_size, new_msg);
    // printf("Encrypt new message HEX: (");
    // for (int i = 0; i < new_msg_size; i++)
    // {
    //     printf("%02X", new_msg[i]);
    // }
    // printf(")\n");

    // int ret = send(tcp_sock, buf, sizeof(buf), 0);
    int ret = esp_transport_write(transport_tcp, (char *)new_msg, new_msg_size, 5000);
    if (ret < 0)
    {
        ESP_LOGE(TAG, "[%d] - Falha ao enviar dados, errno %d\n", count_msg, errno);
        ret = ESP_FAIL;
    }
    else
    {
        printf("[%d] - Socket ainda está conectado.\n", count_msg);

        char ack_buffer[4];
        int len = esp_transport_read(transport_tcp, ack_buffer, sizeof(ack_buffer) - 1, 5000);
        if (len < 0)
        {
            ESP_LOGE(TAG, "recv failed: esp_transport_read() returned %d, errno %d", len, errno);
            ret = ESP_FAIL;
        }
        else
        {
            ack_buffer[len] = 0;
            if (strcmp(ack_buffer, "ACK") != 0)
            {
                ESP_LOGE(TAG, "recv msg? (%s)", ack_buffer);
                ret = ESP_FAIL;
            }
            ESP_LOGI(TAG, "Send (%d) - Received data: [%d] (%s)", new_msg_size, strlen(ack_buffer), ack_buffer);
            count_msg++;
            ret = ESP_OK;
        }
    }

    if (encrypted_msg)
    {
        free(encrypted_msg);
    }
    if (ret != ESP_OK)
    {
        xEventGroupSetBits(my_event_group, SOCKET_GO_BIT);
    }
    return ret;
}

void init_communication(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    wifi_init_sta();
}

// /*
// esp_err_t tcp_start_connect()
// {
//     char rx_buffer[128];
//     int PORT = 4444;
//     int addr_family = 0;
//     int ip_protocol = 0;

//     struct sockaddr_in dest_addr;
//     dest_addr.sin_addr.s_addr = inet_addr(host_ip);
//     if (IPADDR_ANY == dest_addr.sin_addr.s_addr)
//     {
//         int ret = dns_gethostbyname(host_dns, &dest_addr.sin_addr.s_addr, dns_found_cb, NULL);
//         if (ret != 0)
//         {
//             if (xEventGroupWaitBits(my_event_group, DNS_IP_BIT, true, true, pdMS_TO_TICKS(5000)) != DNS_IP_BIT)
//             {
//                 ESP_LOGE(TAG, "ERRO PARA OBTER O IP DO DNS!!!");
//                 return ESP_FAIL;
//             }
//         }
//         printf("ip: %s [%d]\n", host_ip, ret);
//     }
//     else
//     {
//         printf("ip ok: %s\n", ipaddr_ntoa(&dest_addr.sin_addr.s_addr));
//     }

//     // inet_pton(AF_INET, host_ip, &dest_addr.sin_addr);
//     dest_addr.sin_addr.s_addr = inet_addr(host_ip);
//     dest_addr.sin_family = AF_INET;
//     dest_addr.sin_port = htons(PORT);
//     addr_family = AF_INET;
//     ip_protocol = IPPROTO_IP;

//     tcp_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
//     if (tcp_sock < 0)
//     {
//         ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
//         return ESP_FAIL;
//     }

//     int idle_time = 30;
//     int interval_time = 10;
//     int keepalive_count = 1;
//     int timeout_send = 5;
//     int timeout_recv = 5;
//     if (tcp_client_keepalive_end_timeout(
//             tcp_sock, idle_time, interval_time,
//             keepalive_count, timeout_send, timeout_recv) != ESP_OK)
//     {
//         ESP_LOGE(TAG, "Erro ao configurar keepalive");
//         return ESP_FAIL;
//     }

//     // // Set timeout
//     // struct timeval timeout;
//     // timeout.tv_sec = 10;
//     // timeout.tv_usec = 0;
//     // int ret = setsockopt(tcp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
//     // ESP_LOGI(TAG, "SO_SNDTIMEO %d", ret);
//     // // Set timeout
//     // timeout.tv_sec = 10;
//     // timeout.tv_usec = 0;
//     // ret = setsockopt(tcp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
//     // ESP_LOGI(TAG, "SO_RCVTIMEO %d", ret);

//     ESP_LOGI(TAG, "Socket created, connecting to %s:%d", host_ip, PORT);
//     int err = connect(tcp_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
//     if (err != 0)
//     {
//         ESP_LOGE(TAG, "Socket unable to connect: errno %d", errno);
//         return ESP_FAIL;
//     }
//     ESP_LOGI(TAG, "Successfully connected");
//     return ESP_OK;
// }

// static esp_err_t tcp_client_keepalive_end_timeout(int sockfd, int idle, int interval, int count, int t_send, int t_recv)
// {
//     int keep_idle = idle;         // Tempo em segundos de inatividade antes do primeiro keepalive
//     int keep_interval = interval; // Intervalo entre as mensagens de keepalive, em segundos
//     int keep_count = count;       // número máximo de falhas de keepalive permitidas antes da desconexão
//     struct timeval timeout_send;  // Configurar o timeout de envio
//     struct timeval timeout_recv;  // Configurar o timeout de recebimento
//     timeout_send.tv_sec = t_send;
//     timeout_send.tv_usec = 0;
//     timeout_recv.tv_sec = t_recv;
//     timeout_recv.tv_usec = 0;

//     // Definir as opções de keepalive no socket
//     if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keep_idle, sizeof(keep_idle)) < 0)
//     {
//         ESP_LOGE(TAG, "Erro ao definir SO_KEEPALIVE");
//         return ESP_FAIL;
//     }
//     if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keep_idle, sizeof(keep_idle)) < 0)
//     {
//         ESP_LOGE(TAG, "Erro ao definir TCP_KEEPIDLE");
//         return ESP_FAIL;
//     }
//     if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keep_interval, sizeof(keep_interval)) < 0)
//     {
//         ESP_LOGE(TAG, "Erro ao definir TCP_KEEPINTVL");
//         return ESP_FAIL;
//     }
//     if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keep_count, sizeof(keep_count)) < 0)
//     {
//         ESP_LOGE(TAG, "Erro ao definir TCP_KEEPCNT");
//         return ESP_FAIL;
//     }
//     if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout_send, sizeof(timeout_send)) < 0)
//     {
//         ESP_LOGE(TAG, "Erro ao definir SO_SNDTIMEO");
//         return ESP_FAIL;
//     }
//     if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout_recv, sizeof(timeout_recv)) < 0)
//     {
//         ESP_LOGE(TAG, "Erro ao definir SO_RCVTIMEO");
//         return ESP_FAIL;
//     }

//     return ESP_OK;
// }

// esp_err_t tcp_stop_connect()
// {
//     if (tcp_sock != -1)
//     {
//         ESP_LOGE(TAG, "Shutting down socket and restarting...");
//         shutdown(tcp_sock, 0);
//         close(tcp_sock);
//         tcp_sock = -1;
//         return ESP_OK;
//     }
//     return ESP_FAIL;
// }
// */