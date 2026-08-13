#include "mqtt.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cJSON.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mqtt_client.h"

#include "mesh_config.h"
#include "wifi_config.h"

static const char *TAG = "amaran_mqtt";

static esp_mqtt_client_handle_t s_client;
static bool s_connected;
static const amaran_mqtt_dispatch_t *s_dispatch;

/* Topic strings: we build them once per fixture at startup. The G/M topics
 * are for a separate HA `number` entity (HA's light schema has no native
 * green/magenta control). */
typedef struct {
    char set_topic[96];
    char state_topic[96];
    char gm_set_topic[96];
    char gm_state_topic[96];
} fixture_topics_t;
static fixture_topics_t s_topics[AMARAN_LIGHT_COUNT];

/* Last-known per-fixture state — published to the state topics whenever we
 * accept a command. The desktop/iPad apps remain the ground truth of
 * physical state; this is what HA's UI shows. */
typedef struct {
    bool on;
    int brightness;       /* 0–100 */
    int color_temp_mired; /* exact mireds last set by HA (no round-trip drift) */
    int color_temp_k;     /* derived Kelvin, for the mesh send */
    int hue;              /* 0–360 */
    int sat;              /* 0–100 */
    int gm;               /* -50..+50, 0 = neutral */
    bool is_hs;           /* true: last set was color (hs); false: CCT */
    bool dirty;           /* needs a debounced state publish */
    /* On/off verify-and-retry. Mesh sends are fire-and-forget; a lost
     * on/off PDU leaves the fixture contradicting what we told HA, and the
     * post-command refresh then "corrects" HA back to the stale state (the
     * light stays on after an off, and HA flips back to "on" ~1s later).
     * Track the last commanded on/off so a status reply that contradicts a
     * fresh command triggers a bounded re-send instead of being adopted as
     * an external change. */
    bool cmd_pending;        /* an on/off command awaits status confirmation */
    bool cmd_on;             /* the on/off state we commanded */
    int64_t cmd_deadline_us; /* esp_timer time after which we stop retrying */
    int cmd_retries_left;
    bool retry_due;          /* set in mesh-rx context, consumed by timer */
} fixture_state_t;
static fixture_state_t s_state[AMARAN_LIGHT_COUNT];

/* Debounced state publish. HA fires many commands/sec while a slider is
 * dragged; echoing every one back as a retained message makes the slider
 * fight itself and jump to stale values. Instead we mark fixtures dirty and
 * flush ~350ms after the last command. */
static esp_timer_handle_t s_publish_timer;
#define PUBLISH_DEBOUNCE_US 350000

static void publish_state(int idx)
{
    if (!s_connected) return;
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "state", s_state[idx].on ? "ON" : "OFF");
    cJSON_AddNumberToObject(root, "brightness",
                            (s_state[idx].brightness * 255) / 100);
    /* Report the active color mode + its value so HA's UI tracks it. */
    if (s_state[idx].is_hs) {
        cJSON_AddStringToObject(root, "color_mode", "hs");
        cJSON *color = cJSON_CreateObject();
        cJSON_AddNumberToObject(color, "h", s_state[idx].hue);
        cJSON_AddNumberToObject(color, "s", s_state[idx].sat);
        cJSON_AddItemToObject(root, "color", color);
    } else {
        cJSON_AddStringToObject(root, "color_mode", "color_temp");
        /* Echo the exact mireds HA sent — no kelvin round-trip drift. */
        cJSON_AddNumberToObject(root, "color_temp",
                                s_state[idx].color_temp_mired);
    }
    char *json = cJSON_PrintUnformatted(root);
    esp_mqtt_client_publish(s_client, s_topics[idx].state_topic,
                            json, 0, 0, /*retain*/ 1);
    free(json);
    cJSON_Delete(root);

    /* G/M is a separate number entity — publish its plain-int state. */
    if (AMARAN_LIGHTS[idx].has_gm) {
        char gm_buf[8];
        snprintf(gm_buf, sizeof(gm_buf), "%d", s_state[idx].gm);
        esp_mqtt_client_publish(s_client, s_topics[idx].gm_state_topic,
                                gm_buf, 0, 0, /*retain*/ 1);
    }
}

/* Flush every dirty fixture — fired by the debounce timer. */
static void publish_flush_cb(void *arg)
{
    for (int i = 0; i < AMARAN_LIGHT_COUNT; i++) {
        if (s_state[i].dirty) {
            s_state[i].dirty = false;
            publish_state(i);
        }
    }
}

static void schedule_publish(int idx)
{
    s_state[idx].dirty = true;
    if (!s_publish_timer) return;
    esp_timer_stop(s_publish_timer);
    esp_timer_start_once(s_publish_timer, PUBLISH_DEBOUNCE_US);
}

/* On/off verify-and-retry, send side. amaran_mqtt_report_state() runs in
 * the BLE mesh rx path, so it must not send mesh messages itself; it marks
 * the fixture retry_due and arms this one-shot timer. Mesh sends from the
 * esp_timer task are already the established pattern (refresh_timer_cb in
 * main.c does the same). Each re-send goes through the on_off dispatch,
 * whose schedule_refresh() fetches a fresh status ~600ms later — closing
 * the verify loop. */
static esp_timer_handle_t s_retry_timer;
#define CMD_RETRY_DELAY_US   100000              /* 100ms breather */
#define CMD_VERIFY_WINDOW_US (5 * 1000 * 1000)   /* give up after 5s */
#define CMD_RETRIES          2

static void retry_timer_cb(void *arg)
{
    for (int i = 0; i < AMARAN_LIGHT_COUNT; i++) {
        fixture_state_t *st = &s_state[i];
        if (!st->retry_due) continue;
        st->retry_due = false;
        ESP_LOGW(TAG, "on/off for %s not confirmed — resending on=%d (%d left)",
                 AMARAN_LIGHTS[i].key, st->cmd_on, st->cmd_retries_left);
        s_dispatch->on_off(AMARAN_LIGHTS[i].address, st->cmd_on);
    }
}

/* Publish one HA MQTT-discovery message per fixture. */
static void publish_discovery(void)
{
    for (int i = 0; i < AMARAN_LIGHT_COUNT; i++) {
        const amaran_light_t *l = &AMARAN_LIGHTS[i];

        char unique_id[64];
        snprintf(unique_id, sizeof(unique_id), "%s_%s", DEVICE_ID, l->key);

        char config_topic[160];
        snprintf(config_topic, sizeof(config_topic),
                 "%s/light/%s/config", HA_DISCOVERY_PREFIX, unique_id);

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "name", l->name);
        cJSON_AddStringToObject(root, "unique_id", unique_id);
        cJSON_AddStringToObject(root, "object_id", unique_id);
        cJSON_AddStringToObject(root, "schema", "json");
        cJSON_AddNumberToObject(root, "brightness_scale", 255);
        /* JSON schema: brightness comes free with any color mode. Always
         * expose color_temp; add hs only for RGB-capable fixtures so
         * CCT-only fixtures (e.g. the Halo) don't show a dead color wheel. */
        cJSON_AddBoolToObject(root, "color_mode", true);
        cJSON *modes = cJSON_CreateArray();
        cJSON_AddItemToArray(modes, cJSON_CreateString("color_temp"));
        if (l->has_color) {
            cJSON_AddItemToArray(modes, cJSON_CreateString("hs"));
        }
        cJSON_AddItemToObject(root, "supported_color_modes", modes);
        /* Per-fixture CCT range, in mireds (mired = 1e6 / kelvin). */
        cJSON_AddNumberToObject(root, "min_mireds", 1000000 / l->cct_max);
        cJSON_AddNumberToObject(root, "max_mireds", 1000000 / l->cct_min);
        cJSON_AddStringToObject(root, "command_topic", s_topics[i].set_topic);
        cJSON_AddStringToObject(root, "state_topic", s_topics[i].state_topic);
        cJSON_AddNumberToObject(root, "qos", 0);
        cJSON_AddBoolToObject(root, "retain", true);
        cJSON_AddBoolToObject(root, "optimistic", false);

        cJSON *dev = cJSON_CreateObject();
        cJSON *ids = cJSON_CreateArray();
        cJSON_AddItemToArray(ids, cJSON_CreateString(DEVICE_ID));
        cJSON_AddItemToObject(dev, "identifiers", ids);
        cJSON_AddStringToObject(dev, "name", "amaran ESP32 mesh bridge");
        cJSON_AddStringToObject(dev, "manufacturer", "amaran (Aputure)");
        cJSON_AddStringToObject(dev, "model", "Telink BLE Mesh fixture");
        cJSON_AddItemToObject(root, "device", dev);

        char *json = cJSON_PrintUnformatted(root);
        esp_mqtt_client_publish(s_client, config_topic, json, 0, 0,
                                /*retain*/ 1);
        ESP_LOGI(TAG, "discovery published: %s", config_topic);
        free(json);
        cJSON_Delete(root);

        /* G/M: a separate HA `number` entity (the light schema has no
         * green/magenta control). -50..+50, 0 = neutral. */
        if (l->has_gm) {
            char gm_uid[80], gm_topic[176];
            snprintf(gm_uid, sizeof(gm_uid), "%s_gm", unique_id);
            snprintf(gm_topic, sizeof(gm_topic), "%s/number/%s/config",
                     HA_DISCOVERY_PREFIX, gm_uid);
            char gm_name[80];
            snprintf(gm_name, sizeof(gm_name), "%s G/M", l->name);

            cJSON *g = cJSON_CreateObject();
            cJSON_AddStringToObject(g, "name", gm_name);
            cJSON_AddStringToObject(g, "unique_id", gm_uid);
            cJSON_AddStringToObject(g, "object_id", gm_uid);
            cJSON_AddStringToObject(g, "command_topic", s_topics[i].gm_set_topic);
            cJSON_AddStringToObject(g, "state_topic", s_topics[i].gm_state_topic);
            /* -10 = full green, 0 = neutral, +10 = full magenta. */
            cJSON_AddNumberToObject(g, "min", -10);
            cJSON_AddNumberToObject(g, "max", 10);
            cJSON_AddNumberToObject(g, "step", 1);
            cJSON_AddStringToObject(g, "mode", "slider");
            cJSON_AddStringToObject(g, "icon", "mdi:invert-colors");
            cJSON *gdev = cJSON_CreateObject();
            cJSON *gids = cJSON_CreateArray();
            cJSON_AddItemToArray(gids, cJSON_CreateString(DEVICE_ID));
            cJSON_AddItemToObject(gdev, "identifiers", gids);
            cJSON_AddStringToObject(gdev, "name", "amaran ESP32 mesh bridge");
            cJSON_AddItemToObject(g, "device", gdev);

            char *gjson = cJSON_PrintUnformatted(g);
            esp_mqtt_client_publish(s_client, gm_topic, gjson, 0, 0, 1);
            ESP_LOGI(TAG, "discovery published: %s", gm_topic);
            free(gjson);
            cJSON_Delete(g);
        } else {
            /* Clear any previously-retained G/M entity for fixtures that
             * don't support it (e.g. the Halo after a capability fix) by
             * publishing an empty retained payload to its config topic. */
            char gm_uid[80], gm_topic[176];
            snprintf(gm_uid, sizeof(gm_uid), "%s_gm", unique_id);
            snprintf(gm_topic, sizeof(gm_topic), "%s/number/%s/config",
                     HA_DISCOVERY_PREFIX, gm_uid);
            esp_mqtt_client_publish(s_client, gm_topic, "", 0, 0, 1);
            ESP_LOGI(TAG, "discovery cleared: %s", gm_topic);
        }
    }
}

/* Parse one HA JSON-schema command for a given fixture and dispatch to
 * the mesh send callbacks. After dispatching, update our local state and
 * republish on the state topic so HA's UI reflects it. */
static void handle_command_for(int idx, const char *payload, int len)
{
    cJSON *root = cJSON_ParseWithLength(payload, len);
    if (!root) {
        ESP_LOGW(TAG, "bad json on set topic");
        return;
    }
    uint16_t dst = AMARAN_LIGHTS[idx].address;

    cJSON *state = cJSON_GetObjectItemCaseSensitive(root, "state");
    cJSON *bri = cJSON_GetObjectItemCaseSensitive(root, "brightness");
    cJSON *ct = cJSON_GetObjectItemCaseSensitive(root, "color_temp");
    cJSON *color = cJSON_GetObjectItemCaseSensitive(root, "color");

    bool wants_on = s_state[idx].on;
    if (cJSON_IsString(state)) {
        wants_on = (strcmp(state->valuestring, "ON") == 0);
    }

    int wants_brightness = s_state[idx].brightness;
    if (cJSON_IsNumber(bri)) {
        int v = (bri->valueint * 100) / 255;
        if (v < 0) v = 0;
        if (v > 100) v = 100;
        wants_brightness = v;
    }

    /* On/off first — a sleeping fixture won't accept other commands until
     * it's woken. */
    if (wants_on != s_state[idx].on) {
        s_dispatch->on_off(dst, wants_on);
        s_state[idx].on = wants_on;
        /* Arm verify-and-retry — see amaran_mqtt_report_state(). */
        s_state[idx].cmd_pending = true;
        s_state[idx].cmd_on = wants_on;
        s_state[idx].cmd_deadline_us = esp_timer_get_time()
                                       + CMD_VERIFY_WINDOW_US;
        s_state[idx].cmd_retries_left = CMD_RETRIES;
    }

    if (wants_on) {
        /* A single HA command typically carries exactly one of:
         *   color (hs), color_temp, or brightness.
         * Handle whichever is present; fall through to a brightness-only
         * update otherwise. */
        if (cJSON_IsObject(color)) {
            cJSON *h = cJSON_GetObjectItemCaseSensitive(color, "h");
            cJSON *s = cJSON_GetObjectItemCaseSensitive(color, "s");
            int hue = cJSON_IsNumber(h) ? (int)h->valuedouble : s_state[idx].hue;
            int sat = cJSON_IsNumber(s) ? (int)s->valuedouble : s_state[idx].sat;
            s_dispatch->hsi(dst, hue, sat, wants_brightness);
            s_state[idx].is_hs = true;
            s_state[idx].hue = hue;
            s_state[idx].sat = sat;
            s_state[idx].brightness = wants_brightness;
        } else if (cJSON_IsNumber(ct) && ct->valueint > 0) {
            /* Store the exact mireds HA sent; derive kelvin only for the
             * mesh send. Echoing the exact mireds back stops the slider
             * from drifting/jumping. */
            int mireds = ct->valueint;
            int kelvin = 1000000 / mireds;
            s_dispatch->cct(dst, kelvin, wants_brightness, s_state[idx].gm);
            s_state[idx].is_hs = false;
            s_state[idx].color_temp_mired = mireds;
            s_state[idx].color_temp_k = kelvin;
            s_state[idx].brightness = wants_brightness;
        } else if (wants_brightness != s_state[idx].brightness) {
            /* Pure brightness change — preserves current color/CCT on the
             * fixture (Telink 0x8f intensity packet). */
            s_dispatch->brightness(dst, wants_brightness);
            s_state[idx].brightness = wants_brightness;
        }
    }

    cJSON_Delete(root);
    schedule_publish(idx);
}

/* G/M number command: payload is a plain integer -50..+50. Re-send CCT with
 * the stored kelvin + brightness so the tint takes effect immediately (only
 * meaningful in CCT mode; we still store it for HS→CCT transitions). */
static void handle_gm_for(int idx, const char *payload, int len)
{
    char buf[16];
    int n = len < (int)sizeof(buf) - 1 ? len : (int)sizeof(buf) - 1;
    memcpy(buf, payload, n);
    buf[n] = '\0';
    int gm = atoi(buf);
    if (gm < -10) gm = -10;
    if (gm > 10) gm = 10;
    s_state[idx].gm = gm;

    if (s_state[idx].on && !s_state[idx].is_hs) {
        int kelvin = s_state[idx].color_temp_k > 0
                         ? s_state[idx].color_temp_k : 4700;
        s_dispatch->cct(AMARAN_LIGHTS[idx].address, kelvin,
                        s_state[idx].brightness, gm);
    }
    schedule_publish(idx);
}

static int idx_by_addr(uint16_t addr)
{
    for (int i = 0; i < AMARAN_LIGHT_COUNT; i++) {
        if (AMARAN_LIGHTS[i].address == addr) {
            return i;
        }
    }
    return -1;
}

void amaran_mqtt_report_state(uint16_t addr, bool on, bool is_hs,
                              int brightness, int cct_kelvin, int gm,
                              int hue, int sat)
{
    int i = idx_by_addr(addr);
    if (i < 0) {
        return;
    }
    fixture_state_t *st = &s_state[i];
    bool changed = false;

    /* On/off verify-and-retry, receive side. If this status contradicts an
     * on/off we commanded within the last few seconds, the mesh PDU was
     * lost — re-send the command instead of adopting the stale state. Once
     * retries are exhausted or the window passes, fall through and adopt:
     * genuine external changes (phone app, physical knob) still flow to HA
     * as before. */
    if (st->cmd_pending) {
        if (on == st->cmd_on) {
            st->cmd_pending = false;             /* confirmed — all good */
        } else if (st->cmd_retries_left > 0 &&
                   esp_timer_get_time() < st->cmd_deadline_us) {
            st->cmd_retries_left--;
            st->retry_due = true;
            if (s_retry_timer) {
                esp_timer_stop(s_retry_timer);
                esp_timer_start_once(s_retry_timer, CMD_RETRY_DELAY_US);
            }
            return;                              /* don't adopt; retry */
        } else {
            st->cmd_pending = false;             /* give up; adopt truth */
        }
    }

    /* Thresholds suppress the echo of our own commands (the fixture reads
     * back ~exactly what we set) while still catching genuine external
     * changes from the desktop / iOS app or a physical knob. */
    if (on != st->on) {
        st->on = on;
        changed = true;
    }

    if (on) {
        if (abs(brightness - st->brightness) > 2) {
            st->brightness = brightness;
            changed = true;
        }
        if (is_hs != st->is_hs) {
            st->is_hs = is_hs;
            changed = true;
        }
        if (is_hs) {
            if (abs(hue - st->hue) > 3) {
                st->hue = hue;
                changed = true;
            }
            if (abs(sat - st->sat) > 3) {
                st->sat = sat;
                changed = true;
            }
        } else {
            if (cct_kelvin > 0 && abs(cct_kelvin - st->color_temp_k) > 60) {
                st->color_temp_k = cct_kelvin;
                st->color_temp_mired = 1000000 / cct_kelvin;
                changed = true;
            }
            if (gm != st->gm) {
                st->gm = gm;
                changed = true;
            }
        }
    }

    if (changed) {
        ESP_LOGI(TAG, "external change on %s -> publish", AMARAN_LIGHTS[i].key);
        schedule_publish(i);
    }
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected");
        s_connected = true;
        publish_discovery();
        for (int i = 0; i < AMARAN_LIGHT_COUNT; i++) {
            esp_mqtt_client_subscribe(s_client, s_topics[i].set_topic, 0);
            if (AMARAN_LIGHTS[i].has_gm) {
                esp_mqtt_client_subscribe(s_client, s_topics[i].gm_set_topic, 0);
            }
            publish_state(i);
        }
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT disconnected");
        s_connected = false;
        break;
    case MQTT_EVENT_DATA: {
        for (int i = 0; i < AMARAN_LIGHT_COUNT; i++) {
            int tlen = strlen(s_topics[i].set_topic);
            if (event->topic_len == tlen &&
                memcmp(event->topic, s_topics[i].set_topic, tlen) == 0) {
                ESP_LOGI(TAG, "cmd %.*s: %.*s",
                         event->topic_len, event->topic,
                         event->data_len, event->data);
                handle_command_for(i, event->data, event->data_len);
                break;
            }
            int glen = strlen(s_topics[i].gm_set_topic);
            if (AMARAN_LIGHTS[i].has_gm && event->topic_len == glen &&
                memcmp(event->topic, s_topics[i].gm_set_topic, glen) == 0) {
                ESP_LOGI(TAG, "gm %.*s: %.*s",
                         event->topic_len, event->topic,
                         event->data_len, event->data);
                handle_gm_for(i, event->data, event->data_len);
                break;
            }
        }
        break;
    }
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT error");
        break;
    default:
        break;
    }
}

int amaran_mqtt_start(const amaran_mqtt_dispatch_t *dispatch)
{
    s_dispatch = dispatch;

    for (int i = 0; i < AMARAN_LIGHT_COUNT; i++) {
        snprintf(s_topics[i].set_topic, sizeof(s_topics[i].set_topic),
                 "%s/%s/set", MQTT_TOPIC_PREFIX, AMARAN_LIGHTS[i].key);
        snprintf(s_topics[i].state_topic, sizeof(s_topics[i].state_topic),
                 "%s/%s/state", MQTT_TOPIC_PREFIX, AMARAN_LIGHTS[i].key);
        snprintf(s_topics[i].gm_set_topic, sizeof(s_topics[i].gm_set_topic),
                 "%s/%s/gm/set", MQTT_TOPIC_PREFIX, AMARAN_LIGHTS[i].key);
        snprintf(s_topics[i].gm_state_topic, sizeof(s_topics[i].gm_state_topic),
                 "%s/%s/gm/state", MQTT_TOPIC_PREFIX, AMARAN_LIGHTS[i].key);
        s_state[i].on = false;
        s_state[i].brightness = 100;
        s_state[i].color_temp_k = 4700;
        s_state[i].color_temp_mired = 1000000 / 4700;
        s_state[i].hue = 0;
        s_state[i].sat = 0;
        s_state[i].gm = 0;
        s_state[i].is_hs = false;   /* start in CCT mode */
        s_state[i].dirty = false;
    }

    const esp_timer_create_args_t pub_args = {
        .callback = publish_flush_cb,
        .name = "amaran_mqtt_pub",
    };
    esp_timer_create(&pub_args, &s_publish_timer);

    const esp_timer_create_args_t retry_args = {
        .callback = retry_timer_cb,
        .name = "amaran_mqtt_retry",
    };
    esp_timer_create(&retry_args, &s_retry_timer);

    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = MQTT_URI,
    };
    if (strlen(MQTT_USERNAME) > 0) {
        cfg.credentials.username = MQTT_USERNAME;
        cfg.credentials.authentication.password = MQTT_PASSWORD;
    }

    s_client = esp_mqtt_client_init(&cfg);
    if (!s_client) return -1;
    esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID,
                                   mqtt_event_handler, NULL);
    esp_mqtt_client_start(s_client);
    return 0;
}

bool amaran_mqtt_is_connected(void)
{
    return s_connected;
}
