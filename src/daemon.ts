#!/usr/bin/env npx tsx
/**
 * Amaran Light Daemon
 *
 * Stays connected to the lights over BLE and accepts commands via a Unix socket.
 * Start: npm run daemon:start  (or amaran start)
 * Stop:  npm run daemon:stop   (or amaran stop)
 */

import * as net from "net";
import * as http from "http";
import * as fs from "fs";
import * as path from "path";
import { SOCKET_PATH, PID_PATH } from "./daemon-paths.js";
import { loadConfig, type LightConfig } from "./config.js";
import { MeshController } from "./mesh-controller.js";

export { SOCKET_PATH, PID_PATH } from "./daemon-paths.js";

async function runDaemon() {
  const config = loadConfig();
  const ctrl = new MeshController(config);

  // ── Connect ─────────────────────────────────────────────────────────────────
  console.log("Connecting to lights...");
  if (!(await ctrl.connect())) {
    console.error("Failed to connect. Is the Amaran Desktop app closed?");
    process.exit(1);
  }
  await ctrl.waitForBeacon(4000);
  await ctrl.setupProxyFilter();
  console.log("Ready. Listening on", SOCKET_PATH);

  // ── Clean up stale socket ────────────────────────────────────────────────────
  if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH);
  fs.writeFileSync(PID_PATH, String(process.pid));

  // ── Optional MQTT state publisher ────────────────────────────────────────────
  // Publishes state to HA whenever any command runs (CLI, HTTP, or MQTT bridge).
  // State is only published after the first real command — no guessing initial state.
  let mqttPublish: ((lightKey: string, state: object) => void) | null = null;
  let mqttShutdown: (() => void) | null = null;

  if (config.mqtt) {
    const mqttCfg = config.mqtt;
    const discoveryPrefix = mqttCfg.discoveryPrefix ?? "homeassistant";
    const topicPrefix     = mqttCfg.topicPrefix     ?? "amaran";

    // Dynamically import so mqtt is only loaded when actually configured
    const { connect: mqttConnect } = await import("mqtt");
    const mqttClient = mqttConnect(mqttCfg.broker, {
      username: mqttCfg.username,
      password: mqttCfg.password,
      reconnectPeriod: 5000,
      connectTimeout: 10000,
      will: { topic: `${topicPrefix}/status`, payload: "offline", retain: true, qos: 1 },
    });

    const haToPercent = (v: number) => Math.round((v / 255) * 100);
    const miredsToKelvin = (m: number) => Math.round(1000000 / m);

    // Subscribe to HA command topics and forward to runCommand
    mqttClient.subscribe(`${topicPrefix}/+/set`);
    mqttClient.on("message", async (topic: string, message: Buffer) => {
      const match = topic.match(new RegExp(`^${topicPrefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/([^/]+)/set$`));
      if (!match) return;
      const lightKey = match[1];
      let cmd: any;
      try { cmd = JSON.parse(message.toString()); } catch { return; }

      try {
        if (cmd.state !== undefined) {
          const on = String(cmd.state).toUpperCase() === "ON";
          await runCommand({ cmd: on ? "on" : "off", args: [], light: lightKey });
          if (!on) return;
        }
        if (cmd.color_temp !== undefined) {
          const b = cmd.brightness !== undefined ? haToPercent(cmd.brightness) : 80;
          await runCommand({ cmd: "cct", args: [String(b), String(miredsToKelvin(cmd.color_temp)), "0"], light: lightKey });
        } else if (cmd.hs_color !== undefined) {
          const b = cmd.brightness !== undefined ? haToPercent(cmd.brightness) : 80;
          await runCommand({ cmd: "hsi", args: [String(b), String(cmd.hs_color[0]), String(cmd.hs_color[1])], light: lightKey });
        } else if (cmd.brightness !== undefined) {
          await runCommand({ cmd: "brightness", args: [String(haToPercent(cmd.brightness))], light: lightKey });
        }
      } catch (e: any) {
        console.warn(`MQTT command failed for ${lightKey}:`, e.message);
      }
    });

    mqttClient.on("connect", () => {
      console.log("MQTT connected — publishing discovery");
      mqttClient.publish(`${topicPrefix}/status`, "online", { retain: true });

      for (const light of ctrl.lights) {
        const kelvinToMireds = (k: number) => Math.round(1000000 / k);
        const discovery = {
          name: light.name,
          unique_id: `amaran_${light.key}`,
          schema: "json",
          command_topic: `${topicPrefix}/${light.key}/set`,
          state_topic:   `${topicPrefix}/${light.key}/state`,
          availability_topic: `${topicPrefix}/status`,
          supported_color_modes: ["color_temp", "hs"],
          brightness_scale: 255,
          min_mireds: kelvinToMireds(7500),
          max_mireds: kelvinToMireds(2500),
          device: {
            identifiers: [`amaran_${light.key}`],
            name: light.name,
            model: "Amaran Light",
            manufacturer: "Aputure",
          },
        };
        mqttClient.publish(
          `${discoveryPrefix}/light/amaran_${light.key}/config`,
          JSON.stringify(discovery),
          { retain: true }
        );
      }
    });

    mqttClient.on("error", (err: any) => {
      console.warn("MQTT:", err.code ?? err.message);
    });

    mqttPublish = (lightKey: string, state: object) => {
      if (mqttClient.connected) {
        mqttClient.publish(`${topicPrefix}/${lightKey}/state`, JSON.stringify(state), { retain: true });
      }
    };

    mqttShutdown = () => {
      mqttClient.publish(`${topicPrefix}/status`, "offline", { retain: true, qos: 1 }, () => {
        mqttClient.end(true);
      });
      setTimeout(() => mqttClient.end(true), 2000);
    };
  }

  // Per-light state tracker (updated after each command, published to MQTT)
  const lightStates = new Map<string, {
    state: "ON" | "OFF";
    brightness: number;        // HA scale 0-255
    color_mode: "color_temp" | "hs";
    color_temp?: number;       // mireds
    hs_color?: [number, number];
  }>();

  function publishStateFor(lightKey: string) {
    const s = lightStates.get(lightKey);
    if (s && mqttPublish) mqttPublish(lightKey, s);
  }

  function publishStateForAll() {
    for (const light of ctrl.lights) publishStateFor(light.key);
  }

  function updateState(addr: number, patch: object) {
    const lights = addr === 0xffff ? ctrl.lights : ctrl.lights.filter(l => l.address === addr);
    for (const light of lights) {
      const prev = lightStates.get(light.key) ?? {
        state: "ON" as const, brightness: 255, color_mode: "color_temp" as const, color_temp: 178
      };
      lightStates.set(light.key, { ...prev, ...patch });
      publishStateFor(light.key);
    }
  }

  // ── Helper: resolve light address from key or "all" ─────────────────────────
  function resolveTargets(lightKey?: string): number[] {
    if (!lightKey || lightKey === "all") return [0xffff];
    const light = ctrl.lights.find(l => l.key === lightKey);
    if (!light) throw new Error(`Unknown light: "${lightKey}". Known: ${ctrl.lights.map(l => l.key).join(", ")}`);
    return [light.address];
  }

  // ── Run a command sent from a CLI client ─────────────────────────────────────
  async function runCommand(req: { cmd: string; args: string[]; light?: string }): Promise<string> {
    const { cmd, args, light } = req;
    const targets = resolveTargets(light);

    for (const addr of targets) {
      const lightName = ctrl.lights.find(l => l.address === addr)?.name ?? (addr === 0xffff ? "all" : `0x${addr.toString(16)}`);

      const haB = (pct: number) => Math.round((Math.max(0, Math.min(100, pct)) / 100) * 255);
      const kToM = (k: number) => Math.round(1000000 / k);

      switch (cmd) {
        case "on":
          console.log(`Turning ${lightName} ON`);
          await ctrl.setOnOffBlast(addr, true);
          updateState(addr, { state: "ON" });
          break;
        case "off":
          console.log(`Turning ${lightName} OFF`);
          await ctrl.setOnOffBlast(addr, false);
          updateState(addr, { state: "OFF" });
          break;
        case "brightness": {
          const pct = parseFloat(args[0]);
          if (isNaN(pct)) throw new Error("brightness requires a number 0-100");
          console.log(`${lightName} brightness → ${pct}%`);
          await ctrl.setBrightness(addr, pct);
          updateState(addr, { state: "ON", brightness: haB(pct) });
          break;
        }
        case "cct": {
          const b = parseFloat(args[0]);
          const k = parseFloat(args[1]);
          const gm = args[2] ? parseFloat(args[2]) : 0;
          if (isNaN(b) || isNaN(k)) throw new Error("cct requires brightness and kelvin");
          console.log(`${lightName} CCT → ${b}%, ${k}K, GM ${gm}`);
          await ctrl.setCCT(addr, b, k, gm);
          updateState(addr, { state: "ON", brightness: haB(b), color_mode: "color_temp", color_temp: kToM(k), hs_color: undefined });
          break;
        }
        case "hsi":
        case "hsl": {
          const b = parseFloat(args[0]);
          const h = parseFloat(args[1]);
          const s = parseFloat(args[2]);
          if (isNaN(b) || isNaN(h) || isNaN(s)) throw new Error("hsi requires brightness, hue, saturation");
          console.log(`${lightName} HSI → ${b}%, hue ${h}°, sat ${s}%`);
          await ctrl.setHSL(addr, b, h, s);
          updateState(addr, { state: "ON", brightness: haB(b), color_mode: "hs", hs_color: [h, s], color_temp: undefined });
          break;
        }
        case "ping":
          return "pong";
        case "stop":
          console.log("Stop requested. Disconnecting...");
          await ctrl.disconnect();
          cleanup();
          process.exit(0);
          break;
        case "lights":
          return JSON.stringify(ctrl.lights);
        default:
          throw new Error(`Unknown command: ${cmd}`);
      }
    }
    // Nudge fixtures to broadcast their new state so the ESP32 bridge / desktop
    // app pick up the change immediately rather than on the next poll. Mirrors
    // the firmware's schedule_refresh().
    if (["on", "off", "brightness", "cct", "hsi", "hsl"].includes(cmd)) {
      const refreshAddrs = targets.includes(0xffff)
        ? ctrl.lights.map((l: any) => l.address)
        : targets;
      for (const a of refreshAddrs) {
        await ctrl.statusRequest(a);
        await new Promise(r => setTimeout(r, 80));
      }
    }
    return "ok";
  }

  // ── Unix socket server ───────────────────────────────────────────────────────
  const server = net.createServer(socket => {
    let buf = "";
    socket.on("data", chunk => {
      buf += chunk.toString();
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        let req: any;
        try { req = JSON.parse(line); } catch {
          socket.write(JSON.stringify({ error: "Invalid JSON" }) + "\n");
          continue;
        }
        runCommand(req)
          .then(result => socket.write(JSON.stringify({ ok: true, result }) + "\n"))
          .catch(err => socket.write(JSON.stringify({ ok: false, error: err.message }) + "\n"));
      }
    });
    socket.on("error", () => {});
  });

  server.listen(SOCKET_PATH, () => {
    console.log(`Daemon PID ${process.pid} running`);
  });

  // ── HTTP REST server ─────────────────────────────────────────────────────────
  const httpCfg = config.http ?? { port: 2708, host: "0.0.0.0" };

  function readBody(req: http.IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
      let raw = "";
      req.on("data", c => { raw += c; });
      req.on("end", () => {
        if (!raw) { resolve({}); return; }
        try { resolve(JSON.parse(raw)); } catch { reject(new Error("Invalid JSON body")); }
      });
    });
  }

  function jsonResponse(res: http.ServerResponse, status: number, body: object) {
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    });
    res.end(JSON.stringify(body));
  }

  const httpServer = http.createServer(async (req, res) => {
    // CORS preflight
    if (req.method === "OPTIONS") { jsonResponse(res, 204, {}); return; }

    // Optional API key auth
    if (httpCfg.apiKey) {
      const authHeader = req.headers["authorization"] ?? "";
      if (authHeader !== `Bearer ${httpCfg.apiKey}`) {
        jsonResponse(res, 401, { ok: false, error: "Unauthorized" });
        return;
      }
    }

    const url = req.url ?? "/";
    const method = req.method ?? "GET";

    try {
      // GET / or GET /lights — list lights / health check
      if (method === "GET" && (url === "/" || url === "/lights")) {
        jsonResponse(res, 200, { ok: true, lights: ctrl.lights, daemon: true, connected: ctrl.connected });
        return;
      }

      // Writes are fire-and-forget, so a 200 with the link down would be a
      // lie. Say so instead and let the caller decide what to do.
      if (method === "POST" && url.startsWith("/lights") && !ctrl.connected) {
        jsonResponse(res, 503, { ok: false, error: "BLE mesh link down" });
        return;
      }

      // Route: POST /lights/on  or  POST /lights/off
      const allMatch = url.match(/^\/lights\/(on|off)$/);
      if (method === "POST" && allMatch) {
        const result = await runCommand({ cmd: allMatch[1], args: [] });
        jsonResponse(res, 200, { ok: true, result });
        return;
      }

      // Route: POST /lights/:key/on|off|brightness|cct|hsi
      const lightMatch = url.match(/^\/lights\/([^/]+)\/([^/]+)$/);
      if (method === "POST" && lightMatch) {
        const [, lightKey, cmd] = lightMatch;
        const body = await readBody(req);
        let args: string[] = [];
        if (cmd === "brightness" && body.value !== undefined) args = [String(body.value)];
        if (cmd === "cct") args = [String(body.brightness ?? 80), String(body.kelvin ?? 5600), String(body.gm ?? 0)];
        if (cmd === "hsi" || cmd === "hsl") args = [String(body.brightness ?? 80), String(body.hue ?? 0), String(body.saturation ?? 100)];
        const result = await runCommand({ cmd, args, light: lightKey === "all" ? undefined : lightKey });
        jsonResponse(res, 200, { ok: true, result });
        return;
      }

      jsonResponse(res, 404, { ok: false, error: `No route for ${method} ${url}` });
    } catch (e: any) {
      jsonResponse(res, 400, { ok: false, error: e.message });
    }
  });

  httpServer.listen(httpCfg.port, httpCfg.host, () => {
    console.log(`HTTP API → http://${httpCfg.host === "0.0.0.0" ? "localhost" : httpCfg.host}:${httpCfg.port}`);
  });

  function cleanup() {
    if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH);
    if (fs.existsSync(PID_PATH)) fs.unlinkSync(PID_PATH);
  }

  const shutdown = async () => {
    mqttShutdown?.();
    httpServer.close();
    await ctrl.disconnect();
    cleanup();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT",  shutdown);
}

// Only run as daemon when this file is the main entry point, not when imported.
import { fileURLToPath } from "url";
if (process.argv[1] && (
  process.argv[1] === fileURLToPath(import.meta.url) ||
  process.argv[1].endsWith("daemon.ts") ||
  process.argv[1].endsWith("daemon.js")
)) {
  runDaemon().catch(err => {
    console.error("Daemon error:", err.message);
    process.exit(1);
  });
}
