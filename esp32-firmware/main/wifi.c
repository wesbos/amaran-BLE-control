#include "wifi.h"

#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "wifi_config.h"

static const char *TAG = "amaran_wifi";
#define CONNECTED_BIT (1 << 0)

static EventGroupHandle_t s_evt;
static amaran_wifi_got_ip_cb_t s_got_ip_cb;
static int s_retries = 0;

static void event_handler(void *arg, esp_event_base_t base,
                          int32_t event_id, void *data)
{
    if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        s_retries++;
        ESP_LOGW(TAG, "wifi disconnected, retry %d", s_retries);
        xEventGroupClearBits(s_evt, CONNECTED_BIT);
        esp_wifi_connect();
    } else if (base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "got ip " IPSTR, IP2STR(&e->ip_info.ip));
        s_retries = 0;
        xEventGroupSetBits(s_evt, CONNECTED_BIT);
        if (s_got_ip_cb) {
            s_got_ip_cb();
        }
    }
}

int amaran_wifi_start(amaran_wifi_got_ip_cb_t got_ip_cb)
{
    s_got_ip_cb = got_ip_cb;
    s_evt = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_config_t wifi_cfg = { 0 };
    strncpy((char *)wifi_cfg.sta.ssid, WIFI_SSID, sizeof(wifi_cfg.sta.ssid) - 1);
    strncpy((char *)wifi_cfg.sta.password, WIFI_PASSWORD,
            sizeof(wifi_cfg.sta.password) - 1);
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    /* The zero-initialized default is WIFI_FAST_SCAN, which associates to the
     * first SSID match in channel order and never compares signal strength.
     * On a network where several APs broadcast the same SSID, that
     * deterministically picks whichever AP sits on the lowest-numbered
     * channel — possibly a distant one — even with a strong AP in the same
     * room. Scan all channels and pick by RSSI instead; costs a few hundred
     * ms once at connect, and matters here because the bridge holds a
     * persistent MQTT connection whose quality degrades invisibly on a
     * marginal link (entities flap unavailable rather than failing clean). */
    wifi_cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    wifi_cfg.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi sta starting, ssid=%s", WIFI_SSID);
    return 0;
}

bool amaran_wifi_is_connected(void)
{
    if (s_evt == NULL) return false;
    return (xEventGroupGetBits(s_evt) & CONNECTED_BIT) != 0;
}
