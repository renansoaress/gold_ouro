#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"

#include "modules/comm/m_comm.h"
#include "modules/test/m_test.h"
#include "modules/go/m_go.h"

#define LOCAL_TEST 0

static const char *TAG = "[GO - PROJECT]";

void app_main(void)
{
#if LOCAL_TEST
    // TESTE LOCAL
    test();
#else
    init_communication();

    printf(">>> Teste de Criptografia! <<<\n\n");

    int count_loco = 0;
    while (1)
    {
        // char msg[] = "Renan Soares!";
        char msg[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

        esp_err_t ret = send_data(msg, strlen(msg));
        if (ret == ESP_ERR_NOT_FOUND)
        {
            vTaskDelay(pdMS_TO_TICKS(8000));
        }

        vTaskDelay(pdMS_TO_TICKS(2000));
        count_loco++;
    }
#endif
}
