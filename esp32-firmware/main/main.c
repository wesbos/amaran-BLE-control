/*
 * Amaran ESP32 BLE Mesh node firmware.
 *
 * Joins the existing amaran studio mesh as a real node (not as an external
 * proxy client). The node has its own unicast address, a Telink vendor
 * model (CID 0x0211 / MID 0x0000), and shares the BLE Mesh adv channel
 * with the lights, the desktop app, and Sidus Link Pro.
 *
 * Keys are extracted at build time by scripts/generate_config.py from the
 * amaran Desktop app's SQLite database, and self-injected into the mesh
 * stack via internal helpers (no public API exists for that).
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/uart.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "esp_ble_mesh_defs.h"
#include "esp_ble_mesh_common_api.h"
#include "esp_ble_mesh_config_model_api.h"
#include "esp_ble_mesh_networking_api.h"
#include "esp_ble_mesh_provisioning_api.h"
#include "esp_bt.h"
#include "esp_bt_main.h"

/* Internal BLE Mesh headers — no public API exposes "self-provision with
 * pre-known keys." */
#include "mesh/main.h"
#include "local.h"

#include "http.h"
#include "mesh_config.h"
#include "mqtt.h"
#include "telink.h"
#include "wifi.h"

static const char *TAG = "amaran_node";

#define UART_NUM UART_NUM_0
#define UART_BUF_SIZE 256

/* This node's unicast address. The amaran app assigns fixture addresses
 * upward from low values (a seven-fixture rig was observed holding
 * 0x000c–0x001c), so a low value here can silently collide with a real
 * fixture. The symptom is subtle: the colliding fixture never answers a
 * status request, because this node answers for its address. 0x00f0 leaves
 * generous headroom. If you change this on an already-provisioned board,
 * run `idf.py erase-flash` — the old address persists in NVS. */
#define ESP32_UNICAST_ADDR 0x00f0
#define APP_KEY_INDEX      0x0000
#define NET_KEY_INDEX      0x0000
#define DEFAULT_TTL        7

/* Telink uses opcode 0x26 as a single-byte opcode in the SIG range
 * (anything < 0x80 is a 1-byte opcode per BLE Mesh spec). This is NOT a
 * standard 3-byte vendor opcode encoding. The lights run a custom Telink
 * stack that registers this opcode directly, not as a vendor opcode. */
#define VND_OPCODE_SEND   0x26
/* The model itself is still a vendor model (so the AppKey can bind), but
 * its opcode handler accepts the 1-byte form. ESP_BLE_MESH_MODEL_OP_3 is
 * required when registering vendor opcodes in the op array; using the
 * non-3-byte form there would fail. We register a placeholder vendor
 * opcode for receive handling and use the raw 0x26 for sending. */
#define VND_RECV_OPCODE   ESP_BLE_MESH_MODEL_OP_3(AMARAN_VENDOR_OPCODE_BYTE, \
                                                  AMARAN_VENDOR_COMPANY_ID)

/* Mesh model boilerplate — every node needs a Config Server in element 0. */
static esp_ble_mesh_cfg_srv_t config_server = {
    .net_transmit = ESP_BLE_MESH_TRANSMIT(2, 20),
    .relay = ESP_BLE_MESH_RELAY_ENABLED,
    .relay_retransmit = ESP_BLE_MESH_TRANSMIT(2, 20),
    .beacon = ESP_BLE_MESH_BEACON_ENABLED,
    .friend_state = ESP_BLE_MESH_FRIEND_NOT_SUPPORTED,
    .gatt_proxy = ESP_BLE_MESH_GATT_PROXY_ENABLED,
    .default_ttl = DEFAULT_TTL,
};

/* Vendor model 0x0211:0x0000. Opcode 0x26 is the Telink "control/status"
 * verb. We register the opcode so we receive commands targeted at this
 * node from other mesh participants (the desktop app, fixtures echoing
 * status, etc.). */
static esp_ble_mesh_model_op_t vnd_op[] = {
    /* Register both opcode forms so we catch whatever the fixtures use for
     * their status replies: the 3-byte vendor encoding and the raw 1-byte
     * 0x26 (which is what we send). */
    ESP_BLE_MESH_MODEL_OP(VND_RECV_OPCODE, 1),
    ESP_BLE_MESH_MODEL_OP(AMARAN_VENDOR_OPCODE_BYTE, 1),
    ESP_BLE_MESH_MODEL_OP_END,
};

static esp_ble_mesh_model_t root_models[] = {
    ESP_BLE_MESH_MODEL_CFG_SRV(&config_server),
};

static esp_ble_mesh_model_t vnd_models[] = {
    ESP_BLE_MESH_VENDOR_MODEL(AMARAN_VENDOR_COMPANY_ID, 0x0000,
                              vnd_op, NULL, NULL),
};

static esp_ble_mesh_elem_t elements[] = {
    ESP_BLE_MESH_ELEMENT(0, root_models, vnd_models),
};

static esp_ble_mesh_comp_t composition = {
    .cid = AMARAN_VENDOR_COMPANY_ID,
    .element_count = ARRAY_SIZE(elements),
    .elements = elements,
};

static uint8_t dev_uuid[16] = {
    /* Fingerprint: "amaran-esp32" — not a fixture UUID, just an identity for
     * settings storage. The mesh stack won't actually use this in
     * unprovisioned advertising since we self-provision below. */
    'a', 'm', 'a', 'r', 'a', 'n', '-', 'e', 's', 'p', '3', '2', 0, 0, 0, 0,
};

static esp_ble_mesh_prov_t provision = {
    .uuid = dev_uuid,
};

/* ---- callbacks ---------------------------------------------------------- */

/* bt_mesh_provision() is async — the stack only fully transitions to
 * "provisioned" by the time NODE_PROV_COMPLETE_EVT fires. Add AppKey and
 * bind it to the vendor model from here, not synchronously after the
 * provision call. */
static void finish_self_provision(void)
{
    /* AppKey add and model bind both treat "already there" as -EEXIST (-17).
     * That's fine when we boot from previously-persisted NVS. Log & continue
     * either way so we always reach the bind step. */
    int rc = bt_mesh_node_local_app_key_add(NET_KEY_INDEX, APP_KEY_INDEX,
                                            AMARAN_APP_KEY);
    if (rc != 0 && rc != -17 /* EEXIST */) {
        ESP_LOGE(TAG, "node_local_app_key_add rc=%d", rc);
    } else {
        ESP_LOGI(TAG, "app_key add rc=%d", rc);
    }

    rc = bt_mesh_node_bind_app_key_to_model(ESP32_UNICAST_ADDR, 0x0000,
                                            AMARAN_VENDOR_COMPANY_ID,
                                            APP_KEY_INDEX);
    if (rc != 0 && rc != -17) {
        ESP_LOGE(TAG, "bind_app_key_to_model rc=%d", rc);
    } else {
        ESP_LOGI(TAG, "model bind rc=%d", rc);
    }

    ESP_LOGI(TAG, "self-provisioned: addr=0x%04x net_idx=0x%03x app_idx=0x%03x",
             ESP32_UNICAST_ADDR, NET_KEY_INDEX, APP_KEY_INDEX);
}

static void prov_cb(esp_ble_mesh_prov_cb_event_t event,
                    esp_ble_mesh_prov_cb_param_t *param)
{
    switch (event) {
    case ESP_BLE_MESH_PROV_REGISTER_COMP_EVT:
        ESP_LOGI(TAG, "PROV_REGISTER_COMP err=%d",
                 param->prov_register_comp.err_code);
        break;
    case ESP_BLE_MESH_NODE_PROV_COMPLETE_EVT:
        ESP_LOGI(TAG, "NODE_PROV_COMPLETE net_idx=0x%03x addr=0x%04x flags=0x%02x iv=0x%08" PRIx32,
                 param->node_prov_complete.net_idx,
                 param->node_prov_complete.addr,
                 param->node_prov_complete.flags,
                 param->node_prov_complete.iv_index);
        finish_self_provision();
        break;
    case ESP_BLE_MESH_NODE_PROV_RESET_EVT:
        ESP_LOGW(TAG, "NODE_PROV_RESET");
        break;
    default:
        break;
    }
}

static void config_server_cb(esp_ble_mesh_cfg_server_cb_event_t event,
                             esp_ble_mesh_cfg_server_cb_param_t *param)
{
    if (event == ESP_BLE_MESH_CFG_SERVER_STATE_CHANGE_EVT) {
        ESP_LOGI(TAG, "config server state change opcode=0x%04" PRIx32,
                 param->ctx.recv_op);
    }
}

/* Map a fixture mesh address back to its config entry. */
static const amaran_light_t *light_by_addr(uint16_t addr)
{
    for (size_t i = 0; i < AMARAN_LIGHT_COUNT; i++) {
        if (AMARAN_LIGHTS[i].address == addr) {
            return &AMARAN_LIGHTS[i];
        }
    }
    return NULL;
}

/* Strong implementation of the weak hook in the patched BLE Mesh core
 * (net.c). Called with the decrypted access payload of every inbound
 * AppKey-encrypted unsegmented message — in particular the fixtures' 0x26
 * status replies, which are addressed to the provisioner (0x0001) and so
 * never reach the normal model dispatch on this node.
 *
 * We decode the payload (on/off, mode, brightness, cct+gm or hue/sat) and
 * hand it to the MQTT layer, which updates Home Assistant only when it
 * differs materially from what we last commanded — so external changes
 * (desktop / iOS app, physical knob) flow through to HA while our own
 * command echoes are suppressed. */
void amaran_mesh_access_rx(uint16_t src, uint16_t dst,
                           const uint8_t *data, uint16_t len)
{
    if (len < 11 || data[0] != VND_OPCODE_SEND) {
        return;                         /* not a 10-byte Telink 0x26 payload */
    }
    amaran_status_t st;
    if (!amaran_telink_decode_status(data + 1, &st)) {
        return;                         /* 0x0a diagnostic page or bad checksum */
    }

    const amaran_light_t *l = light_by_addr(src);
    ESP_LOGI(TAG, "STATUS %s on=%d %s bri=%u%% cct=%uK gm=%d hue=%u sat=%u",
             l ? l->key : "?", st.on, st.is_hs ? "hsi" : "cct",
             st.intensity / 10, st.cct_kelvin, st.gm, st.hue, st.sat);

    amaran_mqtt_report_state(src, st.on, st.is_hs, st.intensity / 10,
                             st.cct_kelvin, st.gm, st.hue, st.sat);
}

static void custom_model_cb(esp_ble_mesh_model_cb_event_t event,
                            esp_ble_mesh_model_cb_param_t *param)
{
    switch (event) {
    case ESP_BLE_MESH_MODEL_OPERATION_EVT:
        ESP_LOGI(TAG, "vendor msg from 0x%04x opcode=0x%06" PRIx32 " len=%u",
                 param->model_operation.ctx->addr,
                 param->model_operation.opcode,
                 param->model_operation.length);
        ESP_LOG_BUFFER_HEX("vendor data", param->model_operation.msg,
                           param->model_operation.length);
        break;
    case ESP_BLE_MESH_MODEL_SEND_COMP_EVT:
        if (param->model_send_comp.err_code) {
            ESP_LOGE(TAG, "model send err=%d opcode=0x%06" PRIx32,
                     param->model_send_comp.err_code,
                     param->model_send_comp.opcode);
        }
        break;
    default:
        break;
    }
}

/* ---- self-provisioning -------------------------------------------------- */

/* Self-provisioning sequence:
 *   1) esp_ble_mesh_node_prov_enable — sets the BLE_MESH_NODE flag so the
 *      stack considers us a node (without it, bt_mesh_is_provisioned()
 *      stays false even after bt_mesh_provision succeeds).
 *   2) bt_mesh_provision — sets BLE_MESH_VALID, loads NetKey + DeviceKey +
 *      unicast address. Synchronous; on success we're a real mesh node.
 *   3) Disable prov bearers — we're already keyed; don't advertise as
 *      unprovisioned anymore.
 *   4) Add AppKey + bind to vendor model (NODE_PROV_COMPLETE_EVT callback).
 */
static int self_provision(void)
{
    esp_err_t err = esp_ble_mesh_node_prov_enable(
        ESP_BLE_MESH_PROV_ADV | ESP_BLE_MESH_PROV_GATT);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "node_prov_enable err=%d", err);
        return -1;
    }

    /* Random DeviceKey — not on file anywhere, used only for Config traffic
     * which we don't actually need. */
    uint8_t dev_key[16];
    esp_fill_random(dev_key, sizeof(dev_key));

    int rc = bt_mesh_provision(AMARAN_NET_KEY, NET_KEY_INDEX, /*flags*/ 0,
                               AMARAN_IV_INDEX_INITIAL,
                               ESP32_UNICAST_ADDR, dev_key);
    if (rc != 0) {
        ESP_LOGE(TAG, "bt_mesh_provision rc=%d", rc);
        return rc;
    }

    /* Stop advertising as unprovisioned — we're done. */
    esp_ble_mesh_node_prov_disable(
        ESP_BLE_MESH_PROV_ADV | ESP_BLE_MESH_PROV_GATT);
    return 0;
}

/* ---- command sending ---------------------------------------------------- */

/* Forward-declared so the dispatch table below can reference it. */
static int send_telink_to(uint16_t dst, const uint8_t payload[10]);

/* Adapters used by MQTT and HTTP. Same mesh send underneath; just different
 * argument shapes. */
/* Forward decl so the disp_* setters can schedule a follow-up refresh. */
static void schedule_refresh(void);

static void disp_on_off(uint16_t dst, bool on)
{
    uint8_t p[10];
    amaran_telink_onoff(on, p);
    send_telink_to(dst, p);
    schedule_refresh();
}
static void disp_brightness(uint16_t dst, int pct)
{
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    uint8_t p[10];
    amaran_telink_brightness((uint16_t)(pct * 10), p);
    send_telink_to(dst, p);
    schedule_refresh();
}
static void disp_cct(uint16_t dst, int kelvin, int pct, int gm)
{
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    if (gm < -10) gm = -10;
    if (gm > 10) gm = 10;
    uint8_t p[10];
    amaran_telink_cct((uint16_t)kelvin, (uint16_t)(pct * 10), gm, p);
    send_telink_to(dst, p);
    schedule_refresh();
}
static void disp_hsi(uint16_t dst, int hue, int sat, int pct)
{
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    uint8_t p[10];
    amaran_telink_hsi((uint16_t)hue, (uint8_t)sat,
                      (uint16_t)(pct * 10), p);
    send_telink_to(dst, p);
    schedule_refresh();
}

/* Send a Telink status-request to each fixture (or just the one matching
 * dst, if dst is a unicast address). Fixture replies broadcast on the
 * mesh adv channel — that's what makes the iPad / desktop apps refresh
 * their UI. Same effect as Shift+R in Aaron's TUI. */
static void disp_refresh(uint16_t dst)
{
    uint8_t p[10];
    amaran_telink_status_request(p);
    if (dst == AMARAN_GROUP_ALL || dst == AMARAN_BROADCAST) {
        /* Loop per-fixture so each reply is unambiguous. */
        for (size_t i = 0; i < AMARAN_LIGHT_COUNT; i++) {
            send_telink_to(AMARAN_LIGHTS[i].address, p);
            vTaskDelay(pdMS_TO_TICKS(80));
        }
    } else {
        send_telink_to(dst, p);
    }
}

/* Periodic poll: every POLL_INTERVAL_MS, status-request every fixture so
 * we pick up changes made from the desktop / iOS app and reflect them in
 * Home Assistant. Replies arrive in custom_model_cb. */
#define POLL_INTERVAL_MS 12000
static void poll_task(void *arg)
{
    /* Let the mesh + wifi settle before first poll. */
    vTaskDelay(pdMS_TO_TICKS(8000));
    while (1) {
        if (bt_mesh_is_provisioned()) {
            disp_refresh(AMARAN_GROUP_ALL);
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));
    }
}

/* Auto-refresh: after any setter, fire a refresh ~600ms later so the
 * desktop / iPad apps see the new state. The timer is one-shot and we
 * restart it on each setter call, so rapid bursts (HA brightness
 * sliders) collapse into a single refresh after the user stops moving.
 *
 * 600ms picked empirically: long enough for setter mesh PDUs to settle
 * and the fixture to apply the change, short enough that the desktop
 * UI feels live. */
static esp_timer_handle_t s_refresh_timer;
#define REFRESH_DEBOUNCE_US 600000

static void refresh_timer_cb(void *arg)
{
    disp_refresh(AMARAN_GROUP_ALL);
}

static void schedule_refresh(void)
{
    if (!s_refresh_timer) return;
    esp_timer_stop(s_refresh_timer);
    esp_timer_start_once(s_refresh_timer, REFRESH_DEBOUNCE_US);
}

static const amaran_mqtt_dispatch_t g_dispatch = {
    .on_off = disp_on_off,
    .brightness = disp_brightness,
    .cct = disp_cct,
    .hsi = disp_hsi,
    .refresh = disp_refresh,
};

static void on_wifi_ip(void)
{
    ESP_LOGI(TAG, "wifi up; starting mqtt + http");
    amaran_mqtt_start(&g_dispatch);
    amaran_http_start(&g_dispatch);
}

static int send_telink_to(uint16_t dst, const uint8_t payload[10])
{
    esp_ble_mesh_msg_ctx_t ctx = { 0 };
    ctx.net_idx = NET_KEY_INDEX;
    ctx.app_idx = APP_KEY_INDEX;
    ctx.addr = dst;
    ctx.send_ttl = DEFAULT_TTL;

    /* Use the vendor model in element 0. */
    esp_ble_mesh_model_t *model = &vnd_models[0];

    /* send_msg with response_opcode=0 → fire and forget (no ack wait). */
    esp_err_t err = esp_ble_mesh_server_model_send_msg(model, &ctx,
                                                       VND_OPCODE_SEND,
                                                       10, (uint8_t *)payload);
    ESP_LOGI(TAG, "send opcode=0x%06x dst=0x%04x app_idx=0x%03x net_idx=0x%03x len=10 err=%d",
             VND_OPCODE_SEND, dst, APP_KEY_INDEX, NET_KEY_INDEX, err);
    if (err != ESP_OK) {
        return -1;
    }
    return 0;
}

/* ---- CLI ---------------------------------------------------------------- */

static uint16_t resolve_target(const char *id_or_name)
{
    if (id_or_name == NULL || *id_or_name == '\0') {
        return AMARAN_GROUP_ALL;
    }
    char *end;
    long v = strtol(id_or_name, &end, 0);
    if (*end == '\0' && v > 0 && v <= 0xffff) return (uint16_t)v;
    for (size_t i = 0; i < AMARAN_LIGHT_COUNT; i++) {
        if (strcmp(AMARAN_LIGHTS[i].key, id_or_name) == 0) {
            return AMARAN_LIGHTS[i].address;
        }
    }
    return AMARAN_GROUP_ALL;
}

static void print_help(void)
{
    printf("Commands:\n"
           "  on  [target]                 — wake fixture(s)\n"
           "  off [target]                 — sleep fixture(s)\n"
           "  brightness <0-100> [target]\n"
           "  cct <kelvin> <0-100> [target] [gm]\n"
           "  hsi <hue 0-360> <sat 0-100> <int 0-100> [target]\n"
           "  refresh [target]             — poke fixture(s) for status; nudges iPad/desktop apps\n"
           "  list                         — show fixtures\n"
           "  status                       — mesh state\n"
           "  help\n"
           "[target] is a key, decimal address, 0xNNNN, or empty for group-all.\n");
}

static void list_lights(void)
{
    printf("Fixtures (%u):\n", AMARAN_LIGHT_COUNT);
    for (size_t i = 0; i < AMARAN_LIGHT_COUNT; i++) {
        const amaran_light_t *l = &AMARAN_LIGHTS[i];
        printf("  %-20s addr=0x%04x mac=%02X:%02X:%02X:%02X:%02X:%02X name=%s\n",
               l->key, l->address, l->mac[0], l->mac[1], l->mac[2],
               l->mac[3], l->mac[4], l->mac[5], l->name);
    }
    printf("ESP32 node addr=0x%04x\n", ESP32_UNICAST_ADDR);
}

static void handle_command(char *line)
{
    char *tokens[8] = { 0 };
    int n = 0;
    char *save = NULL;
    for (char *t = strtok_r(line, " \t\r\n", &save); t && n < 8;
         t = strtok_r(NULL, " \t\r\n", &save)) {
        tokens[n++] = t;
    }
    if (n == 0) return;

    if (strcmp(tokens[0], "help") == 0) { print_help(); return; }
    if (strcmp(tokens[0], "list") == 0) { list_lights(); return; }
    if (strcmp(tokens[0], "status") == 0) {
        printf("provisioned=%d node_addr=0x%04x\n",
               bt_mesh_is_provisioned(), ESP32_UNICAST_ADDR);
        return;
    }

    if (!bt_mesh_is_provisioned()) {
        printf("not provisioned; can't send yet\n");
        return;
    }

    if (strcmp(tokens[0], "on") == 0 || strcmp(tokens[0], "off") == 0) {
        uint16_t dst = resolve_target(tokens[1]);
        uint8_t payload[10];
        amaran_telink_onoff(strcmp(tokens[0], "on") == 0, payload);
        send_telink_to(dst, payload);
        return;
    }
    if (strcmp(tokens[0], "brightness") == 0 && n >= 2) {
        int pct = atoi(tokens[1]);
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;
        uint16_t dst = resolve_target(n >= 3 ? tokens[2] : NULL);
        uint8_t payload[10];
        amaran_telink_brightness((uint16_t)(pct * 10), payload);
        send_telink_to(dst, payload);
        return;
    }
    if (strcmp(tokens[0], "cct") == 0 && n >= 3) {
        int kelvin = atoi(tokens[1]);
        int pct = atoi(tokens[2]);
        int gm = 0;
        const char *target = NULL;
        if (n >= 4) target = tokens[3];
        if (n >= 5) gm = atoi(tokens[4]);
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;
        uint16_t dst = resolve_target(target);
        uint8_t payload[10];
        amaran_telink_cct((uint16_t)kelvin, (uint16_t)(pct * 10), gm, payload);
        send_telink_to(dst, payload);
        return;
    }
    if (strcmp(tokens[0], "refresh") == 0) {
        uint16_t dst = resolve_target(n >= 2 ? tokens[1] : NULL);
        disp_refresh(dst);
        return;
    }
    if (strcmp(tokens[0], "hsi") == 0 && n >= 4) {
        int hue = atoi(tokens[1]);
        int sat = atoi(tokens[2]);
        int pct = atoi(tokens[3]);
        uint16_t dst = resolve_target(n >= 5 ? tokens[4] : NULL);
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;
        uint8_t payload[10];
        amaran_telink_hsi((uint16_t)hue, (uint8_t)sat,
                          (uint16_t)(pct * 10), payload);
        send_telink_to(dst, payload);
        return;
    }

    printf("unknown command. Type 'help'.\n");
}

static void uart_task(void *arg)
{
    uart_config_t cfg = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_driver_install(UART_NUM, UART_BUF_SIZE * 2, 0, 0, NULL, 0);
    uart_param_config(UART_NUM, &cfg);

    print_help();
    list_lights();
    printf("> ");
    fflush(stdout);

    char line[UART_BUF_SIZE];
    size_t pos = 0;
    while (1) {
        uint8_t c;
        int got = uart_read_bytes(UART_NUM, &c, 1, pdMS_TO_TICKS(100));
        if (got <= 0) continue;
        if (c == '\r' || c == '\n') {
            uart_write_bytes(UART_NUM, "\r\n", 2);
            line[pos] = '\0';
            handle_command(line);
            pos = 0;
            printf("> ");
            fflush(stdout);
            continue;
        }
        if (pos + 1 < sizeof(line)) {
            line[pos++] = (char)c;
            uart_write_bytes(UART_NUM, (const char *)&c, 1);
        }
    }
}

/* ---- entry -------------------------------------------------------------- */

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    /* Bluedroid init (BLE Mesh sits on top). */
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    esp_ble_mesh_register_prov_callback(prov_cb);
    esp_ble_mesh_register_config_server_callback(config_server_cb);
    esp_ble_mesh_register_custom_model_callback(custom_model_cb);

    err = esp_ble_mesh_init(&provision, &composition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ble_mesh_init err=%d", err);
        return;
    }

    /* If NVS already has provisioning state from a previous boot, settings
     * loaded it for us — skip the inject. Otherwise inject our pre-known
     * keys. */
    if (!bt_mesh_is_provisioned()) {
        ESP_LOGI(TAG, "no stored provisioning, self-injecting keys");
        self_provision();
    } else {
        ESP_LOGI(TAG, "already provisioned from NVS");
        finish_self_provision();
    }

    /* Debounced refresh timer — fired ~600ms after the last setter so
     * the desktop / iPad apps get a status reply through the mesh and
     * update their UI. Without this, the apps stay stale unless you hit
     * a manual refresh. */
    const esp_timer_create_args_t refresh_args = {
        .callback = refresh_timer_cb,
        .name = "amaran_refresh",
    };
    esp_timer_create(&refresh_args, &s_refresh_timer);

    xTaskCreate(uart_task, "uart_cli", 4096, NULL, 5, NULL);
    xTaskCreate(poll_task, "amaran_poll", 3072, NULL, 4, NULL);

    /* Bring up Wi-Fi; MQTT + HTTP start from the got-IP callback. Wi-Fi
     * coexists with BLE on the same chip via the software-coex layer
     * enabled in sdkconfig.defaults. */
    amaran_wifi_start(on_wifi_ip);
}
