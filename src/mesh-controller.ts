/**
 * Amaran BLE Mesh Controller — core library
 *
 * Directly controls Amaran lights via Bluetooth Mesh, bypassing the desktop app.
 * Protocol reverse-engineered from com.sidus.link.amaran APK v1.0.70.
 *
 * Import and use MeshController directly, or run via cli.ts.
 */

import * as crypto from "crypto";
// @ts-ignore
import noble from "@abandonware/noble";
import type { Config, LightConfig } from "./config.js";
import * as telink from "./telink.js";

// Provisioner address (0x0001 is standard for SIG mesh provisioner).
const LOCAL_ADDRESS = 0x0001;
const DEFAULT_TTL = 10;
// Group "All" address — typical provisioner default, overridden by config if needed.
const GROUP_ALL = 0xc000;

// ─── BLE UUIDs ───────────────────────────────────────────────────────────────

const PROXY_SERVICE = "1828";
const PROXY_DATA_IN = "2add"; // write mesh messages here
const PROXY_DATA_OUT = "2ade"; // notifications come from here

// ─── Mesh Opcodes (stored as little-endian integers — see Opcode.java) ───────

// All physical controls use the Telink proprietary opcode 0x26.
// Standard BLE Mesh models (Generic OnOff, Light Lightness, CTL) exist on the
// lights and respond, but they are decoupled from the physical LED output.
const OP = {
  TELINK_CMD: 0x26,
};

// ─── Proxy PDU types ─────────────────────────────────────────────────────────

const PROXY_TYPE_NETWORK = 0x00;
const PROXY_TYPE_BEACON = 0x01;
const PROXY_TYPE_PROXY_CONFIG = 0x02;

// ─── Proxy configuration opcodes (BLE Mesh spec §6.5) ────────────────────────

const PROXY_CFG_SET_FILTER_TYPE = 0x00;
const PROXY_CFG_ADD_ADDRESSES   = 0x01;
const PROXY_FILTER_WHITELIST    = 0x00;

// ─── Crypto helpers ──────────────────────────────────────────────────────────

function aesEcbBlock(key: Buffer, data: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function aesCmac(key: Buffer, message: Buffer): Buffer {
  // Generate K1 and K2 subkeys
  const L = aesEcbBlock(key, Buffer.alloc(16, 0));
  const K1 = cmacShiftLeft(L, L[0] & 0x80 ? 0x87 : 0);
  const K2 = cmacShiftLeft(K1, K1[0] & 0x80 ? 0x87 : 0);

  const n = Math.ceil(message.length / 16) || 1;
  const lastComplete = message.length > 0 && message.length % 16 === 0;

  let x = Buffer.alloc(16, 0);

  for (let i = 0; i < n - 1; i++) {
    const block = message.subarray(i * 16, i * 16 + 16);
    for (let j = 0; j < 16; j++) x[j] ^= block[j];
    x = aesEcbBlock(key, x);
  }

  const lastBlock = Buffer.alloc(16, 0);
  if (lastComplete) {
    message.copy(lastBlock, 0, (n - 1) * 16, n * 16);
    for (let j = 0; j < 16; j++) lastBlock[j] ^= K1[j];
  } else {
    const rem = message.length % 16;
    if (rem > 0) message.copy(lastBlock, 0, (n - 1) * 16, (n - 1) * 16 + rem);
    lastBlock[rem] = 0x80;
    for (let j = 0; j < 16; j++) lastBlock[j] ^= K2[j];
  }

  for (let j = 0; j < 16; j++) x[j] ^= lastBlock[j];
  return aesEcbBlock(key, x);
}

function cmacShiftLeft(b: Buffer, xorByte: number): Buffer {
  const out = Buffer.alloc(16);
  let carry = 0;
  for (let i = 15; i >= 0; i--) {
    out[i] = ((b[i] << 1) | carry) & 0xff;
    carry = (b[i] & 0x80) ? 1 : 0;
  }
  if (xorByte) out[15] ^= xorByte;
  return out;
}

function s1(m: Buffer): Buffer {
  return aesCmac(Buffer.alloc(16, 0), m);
}

// k2: derive NID, EncryptionKey, PrivacyKey from NetKey
// Ref: Bluetooth Mesh spec §3.6.5.1 / Encipher.java k2()
function k2(netKey: Buffer): { nid: number; encKey: Buffer; privKey: Buffer } {
  const salt = s1(Buffer.from("smk2"));
  const T = aesCmac(salt, netKey);
  const P = Buffer.from([0x00]); // master security material

  const T1 = aesCmac(T, Buffer.concat([P, Buffer.from([0x01])]));
  const T2 = aesCmac(T, Buffer.concat([T1, P, Buffer.from([0x02])]));
  const T3 = aesCmac(T, Buffer.concat([T2, P, Buffer.from([0x03])]));

  return { nid: T1[15] & 0x7f, encKey: T2, privKey: T3 };
}

// k4: derive AID from AppKey
// Ref: Bluetooth Mesh spec §3.6.5.4 / Encipher.java k4()
function k4(appKey: Buffer): number {
  const salt = s1(Buffer.from("smk4"));
  const T = aesCmac(salt, appKey);
  // SALT_K4_M = "id6\x01" = [0x69, 0x64, 0x36, 0x01]
  const result = aesCmac(T, Buffer.from([0x69, 0x64, 0x36, 0x01]));
  return result[15] & 0x3f;
}

function aesCcmEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer, micLen: number): Buffer {
  const cipher = crypto.createCipheriv("aes-128-ccm", key, nonce, { authTagLength: micLen });
  cipher.setAAD(Buffer.alloc(0), { plaintextLength: plaintext.length });
  const ct = cipher.update(plaintext);
  cipher.final();
  return Buffer.concat([ct, cipher.getAuthTag()]);
}

// ─── Packet construction ─────────────────────────────────────────────────────

// Serialize opcode as little-endian bytes (matching AccessLayerPDU.java toByteArray)
function opcodeBytes(op: number): Buffer {
  const firstByte = op & 0xff;
  if (firstByte < 0x80) return Buffer.from([firstByte]); // 1-byte opcode
  if (firstByte < 0xc0) return Buffer.from([firstByte, (op >> 8) & 0xff]); // 2-byte opcode
  return Buffer.from([firstByte, (op >> 8) & 0xff, (op >> 16) & 0xff]); // 3-byte opcode
}

// Application nonce (13 bytes) — NonceGenerator.java generateAccessNonce()
function appNonce(seq: number, src: number, dst: number, ivIndex: number): Buffer {
  return Buffer.from([
    0x01, // application nonce type
    0x00, // SZMIC=0 << 7
    (seq >> 16) & 0xff,
    (seq >> 8) & 0xff,
    seq & 0xff,
    (src >> 8) & 0xff,
    src & 0xff,
    (dst >> 8) & 0xff,
    dst & 0xff,
    (ivIndex >> 24) & 0xff,
    (ivIndex >> 16) & 0xff,
    (ivIndex >> 8) & 0xff,
    ivIndex & 0xff,
  ]);
}

// Network nonce (13 bytes) — NonceGenerator.java generateNetworkNonce()
function netNonce(ctl: number, ttl: number, seq: number, src: number, ivIndex: number): Buffer {
  return Buffer.from([
    0x00, // network nonce type
    (ctl << 7) | (ttl & 0x7f),
    (seq >> 16) & 0xff,
    (seq >> 8) & 0xff,
    seq & 0xff,
    (src >> 8) & 0xff,
    src & 0xff,
    0x00,
    0x00,
    (ivIndex >> 24) & 0xff,
    (ivIndex >> 16) & 0xff,
    (ivIndex >> 8) & 0xff,
    ivIndex & 0xff,
  ]);
}

// Proxy nonce (13 bytes) — BLE Mesh spec §3.8.5.4
// Same layout as network nonce but type=0x03, byte 1 is always 0x00 (no CTL/TTL).
function proxyNonce(seq: number, src: number, ivIndex: number): Buffer {
  return Buffer.from([
    0x03, // proxy nonce type
    0x00,
    (seq >> 16) & 0xff,
    (seq >> 8) & 0xff,
    seq & 0xff,
    (src >> 8) & 0xff,
    src & 0xff,
    0x00,
    0x00,
    (ivIndex >> 24) & 0xff,
    (ivIndex >> 16) & 0xff,
    (ivIndex >> 8) & 0xff,
    ivIndex & 0xff,
  ]);
}

// Build the full proxy PDU for a mesh access message
// Returns the bytes to write to PROXY_DATA_IN
function buildProxyPDU(
  appKey: Buffer,
  aid: number,
  nid: number,
  encKey: Buffer,
  privKey: Buffer,
  seq: number,
  src: number,
  dst: number,
  ivIndex: number,
  opcode: number,
  params: Buffer
): Buffer {
  // 1. Access PDU = opcode (LE) + params (LE)
  const accessPDU = Buffer.concat([opcodeBytes(opcode), params]);

  // 2. Encrypt access PDU with AppKey → Upper Transport PDU
  const upperEncrypted = aesCcmEncrypt(appKey, appNonce(seq, src, dst, ivIndex), accessPDU, 4);

  // 3. Lower Transport PDU = [AKF=1 | AID(6 bits)] + upper transport
  const lowerTransport = Buffer.concat([Buffer.from([0x40 | (aid & 0x3f)]), upperEncrypted]);

  // 4. Encrypt [DST + lowerTransport] with EncKey → encrypted network payload
  const netPayload = Buffer.concat([
    Buffer.from([(dst >> 8) & 0xff, dst & 0xff]),
    lowerTransport,
  ]);
  const ctl = 0;
  const encryptedPayload = aesCcmEncrypt(
    encKey,
    netNonce(ctl, DEFAULT_TTL, seq, src, ivIndex),
    netPayload,
    4
  );

  // 5. Obfuscate network header: (CTL|TTL, SEQ[2:0], SRC[1:0]) XOR PECB
  const ivi = ivIndex & 1;
  const pecb = computePECB(privKey, ivIndex, encryptedPayload.subarray(0, 7));
  const hdr = Buffer.from([
    (ctl << 7) | (DEFAULT_TTL & 0x7f),
    (seq >> 16) & 0xff,
    (seq >> 8) & 0xff,
    seq & 0xff,
    (src >> 8) & 0xff,
    src & 0xff,
  ]);
  const obfuscated = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) obfuscated[i] = hdr[i] ^ pecb[i];

  // 6. Network PDU = [IVI|NID] + obfuscated header + encrypted payload
  const networkPDU = Buffer.concat([Buffer.from([(ivi << 7) | (nid & 0x7f)]), obfuscated, encryptedPayload]);

  // 7. Proxy PDU = [SAR=0, TYPE=0] + Network PDU
  return Buffer.concat([Buffer.from([PROXY_TYPE_NETWORK]), networkPDU]);
}

// Proxy Configuration PDU (BLE Mesh spec §6.5) — sent BEFORE any mesh commands.
// The Telink SDK always sends Set Filter Type → waits for Filter Status → then Add Addresses
// before marking the connection ready. Without this handshake the proxy silently drops relayed PDUs.
// CTL=1, TTL=0, DST=0x0000, encrypted with EncKey + proxy nonce (type 0x03).
function buildProxyConfigPDU(
  nid: number,
  encKey: Buffer,
  privKey: Buffer,
  seq: number,
  src: number,
  ivIndex: number,
  opcode: number,
  params: Buffer
): Buffer {
  const ctl = 1;
  const ttl = 0;
  const dst = 0x0000;

  // Lower transport PDU: [SEG=0 | Opcode(7)] + params
  const transportPDU = Buffer.concat([Buffer.from([opcode & 0x7f]), params]);

  // Encrypt [DST | transportPDU] with proxy nonce, 4-byte MIC
  const netPayload = Buffer.concat([Buffer.from([(dst >> 8) & 0xff, dst & 0xff]), transportPDU]);
  const encrypted = aesCcmEncrypt(encKey, proxyNonce(seq, src, ivIndex), netPayload, 4);

  // Obfuscate header
  const ivi = ivIndex & 1;
  const pecb = computePECB(privKey, ivIndex, encrypted.subarray(0, 7));
  const hdr = Buffer.from([
    (ctl << 7) | (ttl & 0x7f),
    (seq >> 16) & 0xff,
    (seq >> 8) & 0xff,
    seq & 0xff,
    (src >> 8) & 0xff,
    src & 0xff,
  ]);
  const obfuscated = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) obfuscated[i] = hdr[i] ^ pecb[i];

  const networkPDU = Buffer.concat([Buffer.from([(ivi << 7) | (nid & 0x7f)]), obfuscated, encrypted]);
  return Buffer.concat([Buffer.from([PROXY_TYPE_PROXY_CONFIG]), networkPDU]);
}

// PECB for header obfuscation — NetworkLayerPDU.java createPECB()
function computePECB(privKey: Buffer, ivIndex: number, privacyRandom7: Buffer): Buffer {
  const input = Buffer.alloc(16, 0);
  input[5] = (ivIndex >> 24) & 0xff;
  input[6] = (ivIndex >> 16) & 0xff;
  input[7] = (ivIndex >> 8) & 0xff;
  input[8] = ivIndex & 0xff;
  privacyRandom7.copy(input, 9, 0, 7);
  return aesEcbBlock(privKey, input);
}

// ─── Beacon parsing ───────────────────────────────────────────────────────────

// Parse IV index from a Secure Network Beacon notification
// Returns null if the data is not a valid beacon PDU
function parseIVIndexFromProxy(data: Buffer): number | null {
  if (data.length < 23) return null;
  const type = data[0] & 0x3f; // lower 6 bits
  if (type !== PROXY_TYPE_BEACON) return null;
  const beaconType = data[1];
  if (beaconType !== 0x01) return null; // Secure Network Beacon
  if (data.length < 23) return null;
  // Bytes 11-14 (1 proxy header + 1 beacon type + 1 flags + 8 networkID + 4 ivIndex)
  const ivIndex = data.readUInt32BE(11);
  return ivIndex;
}

// ─── Controller class ────────────────────────────────────────────────────────

export class MeshController {
  private peripheral: any = null;

  // Whether the BLE proxy link is believed to be up. Set on a successful
  // connect, cleared by the disconnect handler in doConnect(). Reads as false
  // until the proxy characteristics exist, since a peripheral without them
  // cannot carry mesh traffic.
  private connectedFlag = false;

  get connected(): boolean {
    return this.connectedFlag && !!this.dataIn && !!this.dataOut;
  }
  private dataIn: any = null;
  private dataOut: any = null;
  private ivIndex = 0;
  // Random start in 12M–16M range: avoids replay rejection between successive runs.
  private seq = parseInt(process.env.MESH_SEQ ?? '') || (12000000 + Math.floor(Math.random() * 4000000));

  private readonly aid: number;
  private readonly nid: number;
  private readonly encKey: Buffer;
  private readonly privKey: Buffer;
  private readonly appKey: Buffer;
  private readonly relayHubUUID: string; // actually the relay hub MAC address
  readonly lights: LightConfig[];

  constructor(config: Config) {
    const netKey = Buffer.from(config.netKey, "hex");
    this.appKey = Buffer.from(config.appKey, "hex");
    const derived = k2(netKey);
    this.nid = derived.nid;
    this.encKey = derived.encKey;
    this.privKey = derived.privKey;
    this.aid = k4(this.appKey);
    this.relayHubUUID = config.relayHub; // MAC address stored as-is
    this.lights = config.lights;
  }

  async connect(preferredMac?: string): Promise<boolean> {
    const self = this;
    return new Promise((resolve) => {
      // Normalize relay hub MAC for comparison
      const hubMac = self.relayHubUUID.toLowerCase().replace(/-/g, ":");
      const knownMacs = self.lights.map(l => l.mac.toLowerCase().replace(/-/g, ":"));
      console.log(`Scanning for lights (relay hub MAC: ${hubMac})...`);
      let found = false;
      const candidates = new Map<string, any>(); // normalized-addr → peripheral

      noble.on("stateChange", async (state: string) => {
        if (state === "poweredOn") await noble.startScanningAsync([], true);
      });

      noble.on("discover", async (p: any) => {
        if (found) return;

        const addr = (p.address || p.id || "").toLowerCase().replace(/-/g, ":");
        const name = (p.advertisement.localName || "").toLowerCase();
        const advServices: string[] = (p.advertisement.serviceUuids || []).map((u: string) => u.toLowerCase());
        const hasMeshProxy = advServices.some(u => u === "1828" || u.startsWith("00001828"));
        const isByMac = knownMacs.includes(addr) || (preferredMac ? addr === preferredMac.toLowerCase().replace(/-/g, ":") : false);
        const isByName = name.includes("slck") || name.includes("amaran") || name.includes("aputure");

        if (!hasMeshProxy && !isByMac && !isByName) return;

        const isHub = addr === hubMac;
        const matchType = hasMeshProxy ? "proxy-svc" : isByMac ? "mac" : "name";
        if (!candidates.has(addr)) {
          console.log(`  Found: ${p.advertisement.localName || addr} (${addr}) [${matchType}]${isHub ? " ← relay hub" : ""}`);
        }
        candidates.set(addr, p);

        if (isHub) {
          found = true;
          noble.stopScanningAsync();
          doConnect(p, addr).then(resolve);
        }
      });

      // After 5s, pick best candidate.
      // Order: matches hubMac (only works if hub config is a BLE UUID on macOS,
      // since noble exposes BLE UUIDs not MACs on darwin) > known-good proxies
      // (Key Light, Back Light) > anything else. Halo's proxy implementation
      // hangs on Set Filter Type writes — avoid it as proxy host.
      const preferredHubUUIDs = [
        "b3ed1263a9304e5132b3edfbb4c71aec", // Key Light
        "d16927ee947b5a0ced73358c29bc4bcd", // Back Light
      ];
      const hubWait = setTimeout(async () => {
        if (found || candidates.size === 0) return;
        found = true;
        await noble.stopScanningAsync();
        let best = candidates.get(hubMac);
        if (!best) {
          for (const uuid of preferredHubUUIDs) {
            if (candidates.has(uuid)) { best = candidates.get(uuid); break; }
          }
        }
        if (!best) best = candidates.values().next().value;
        const addr = (best.address || best.id || "").toLowerCase().replace(/-/g, ":");
        doConnect(best, addr).then(resolve);
      }, 5000);

      setTimeout(async () => {
        clearTimeout(hubWait);
        if (!found) {
          await noble.stopScanningAsync();
          console.error("No Amaran lights found. Make sure the Amaran Desktop app is closed.");
          resolve(false);
        }
      }, 15000);

      async function doConnect(p: any, addr: string): Promise<boolean> {
        console.log(`Connecting to ${p.advertisement.localName || addr} (${addr})...`);
        try {
          await p.connectAsync();
          self.peripheral = p;

          // noble emits this when the light drops the link — after a power
          // cycle, going out of range, or using its onboard knobs. Nothing
          // listened for it before, so the controller went on writing into a
          // dead handle indefinitely.
          p.once("disconnect", () => {
            console.log("BLE link dropped — marking mesh unavailable");
            self.connectedFlag = false;
            self.dataIn = null;
            self.dataOut = null;
            self.peripheral = null;
          });

          const { characteristics } = await p.discoverSomeServicesAndCharacteristicsAsync(
            [PROXY_SERVICE], [PROXY_DATA_IN, PROXY_DATA_OUT]
          );

          for (const c of characteristics) {
            if (c.uuid === PROXY_DATA_IN) self.dataIn = c;
            if (c.uuid === PROXY_DATA_OUT) self.dataOut = c;
          }

          if (!self.dataIn || !self.dataOut) {
            console.error(`Mesh proxy chars not found. Run: npx tsx src/ble-scanner.ts connect ${addr}`);
            return false;
          }

          self.dataOut.on("data", (d: Buffer) => self.onNotify(d));
          await self.dataOut.subscribeAsync();
          self.connectedFlag = true;
          console.log(`Connected to ${p.advertisement.localName || addr}`);
          return true;
        } catch (err) {
          console.error("Connection error:", err);
          return false;
        }
      }
    });
  }

  private ivResolve: ((iv: number) => void) | null = null;
  private beaconReceived = false;
  private filterStatusResolve: (() => void) | null = null;

  private onNotify(data: Buffer): void {
    const type = data[0] & 0x3f;

    if (type === PROXY_TYPE_PROXY_CONFIG) {
      if (this.filterStatusResolve) {
        this.filterStatusResolve();
        this.filterStatusResolve = null;
      }
      return;
    }

    const iv = parseIVIndexFromProxy(data);
    if (iv !== null) {
      this.ivIndex = iv;
      this.beaconReceived = true;
      console.log(`  ← Secure Network Beacon — IV Index: 0x${iv.toString(16).padStart(8, "0")}`);
      if (this.ivResolve) {
        this.ivResolve(iv);
        this.ivResolve = null;
      }
    }
  }

  waitForBeacon(timeoutMs = 5000): Promise<number> {
    return new Promise((resolve) => {
      if (this.beaconReceived) { resolve(this.ivIndex); return; }
      const timer = setTimeout(() => {
        this.ivResolve = null;
        console.log("No beacon received; using IV index 0");
        resolve(0);
      }, timeoutMs);
      this.ivResolve = (iv) => { clearTimeout(timer); resolve(iv); };
    });
  }

  // Wraps a writeAsync with a hard timeout: on macOS+noble, writeWithoutResponse
  // sometimes never resolves its confirmation callback even though the bytes
  // were delivered. We treat slow writes as "fire and forget" after a few seconds.
  private async writeWithTimeout(char: any, data: Buffer, withoutResponse: boolean, ms = 3000): Promise<"ok" | "timeout"> {
    const writeP = char.writeAsync(data, withoutResponse).then(() => "ok" as const);
    const timeoutP = new Promise<"timeout">(r => setTimeout(() => r("timeout"), ms));
    return Promise.race([writeP, timeoutP]);
  }

  // Mirrors what the Telink SDK does in normalConnectPeripheral after subscribing to notifications:
  // 500ms delay → Set Filter Type (whitelist) → wait for Filter Status → Add Addresses.
  async setupProxyFilter(): Promise<void> {
    if (!this.dataIn) throw new Error("Not connected");

    // Match the Telink SDK's 500ms pause between notification subscribe and filter setup.
    await new Promise(r => setTimeout(r, 500));

    // 1. Set Filter Type = whitelist (0x00). The Telink proxy rejects blacklist
    //    silently and stops responding, so whitelist it is.
    const setFilterPDU = buildProxyConfigPDU(
      this.nid, this.encKey, this.privKey,
      this.nextSeq(), LOCAL_ADDRESS, this.ivIndex,
      PROXY_CFG_SET_FILTER_TYPE,
      Buffer.from([PROXY_FILTER_WHITELIST])
    );
    console.log(`  → Proxy: Set Filter Type = Whitelist  ${setFilterPDU.toString("hex")}`);
    await this.writeWithTimeout(this.dataIn, setFilterPDU, true);

    // 2. Wait for Filter Status response (up to 2s)
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        this.filterStatusResolve = null;
        resolve();
      }, 2000);
      this.filterStatusResolve = () => { clearTimeout(timer); resolve(); };
    });

    // 3. Whitelist: us, broadcast, group-all, AND every light address from config.
    //    Adding light addresses means the proxy will forward traffic addressed
    //    to those lights — including commands sent by other proxy clients
    //    (e.g. the Desktop app) that get relayed through our hub.
    const addresses: number[] = [LOCAL_ADDRESS, 0xffff, GROUP_ALL];
    for (const l of this.lights) {
      if (typeof l.address === "number") addresses.push(l.address);
    }
    const addrBuf = Buffer.alloc(addresses.length * 2);
    for (let i = 0; i < addresses.length; i++) addrBuf.writeUInt16BE(addresses[i] & 0xffff, i * 2);
    const addAddrPDU = buildProxyConfigPDU(
      this.nid, this.encKey, this.privKey,
      this.nextSeq(), LOCAL_ADDRESS, this.ivIndex,
      PROXY_CFG_ADD_ADDRESSES,
      addrBuf
    );
    console.log(`  → Proxy: Add Addresses [${addresses.map(a => "0x" + a.toString(16).padStart(4, "0")).join(", ")}]  ${addAddrPDU.toString("hex")}`);
    await this.writeWithTimeout(this.dataIn, addAddrPDU, true);

    // Small settling gap before commands
    await new Promise(r => setTimeout(r, 300));
    console.log("Proxy filter configured — ready");
  }

  private nextSeq(): number {
    this.seq = (this.seq + 1) & 0xffffff;
    return this.seq;
  }

  async send(dst: number, opcode: number, params: Buffer, retries = 3): Promise<void> {
    if (!this.dataIn) throw new Error("Not connected");
    for (let i = 0; i < retries; i++) {
      const seq = this.nextSeq();
      const pdu = buildProxyPDU(
        this.appKey, this.aid, this.nid, this.encKey, this.privKey,
        seq, LOCAL_ADDRESS, dst, this.ivIndex,
        opcode, params
      );
      if (i === 0) console.log(`  → dst=0x${dst.toString(16).padStart(4,"0")} opcode=0x${opcode.toString(16).padStart(4,"0")} try=${i+1}/${retries} payload=${pdu.toString("hex")}`);
      else console.log(`    retry ${i+1} seq=${seq} payload=${pdu.toString("hex")}`);
      await this.writeWithTimeout(this.dataIn, pdu, true, 1500);
      await new Promise(r => setTimeout(r, 80)); // small gap between retries
    }
  }

  // All Telink 0x26 payloads are built by the shared ./telink module, which
  // is ported from the verified ESP32 firmware (telink.c).
  async setOnOffBlast(dst: number, on: boolean): Promise<void> {
    await this.send(dst, OP.TELINK_CMD, telink.onoff(on), 3);
  }

  // intensity 0–1000.
  async setTelinkBrightness(dst: number, intensity: number): Promise<void> {
    await this.send(dst, OP.TELINK_CMD, telink.brightness(intensity), 3);
  }

  // kelvin in K, intensity 0–1000, gm -10..+10 (0 = neutral). The CCT field
  // is kelvin/10 — see telink.ts for the encoding (the old raw-kelvin version
  // overflowed the 10-bit field and produced wrong colors).
  async setTelinkCCT(dst: number, kelvin: number, intensity: number, gm = 0): Promise<void> {
    await this.send(dst, OP.TELINK_CMD, telink.cct(kelvin, intensity, gm), 3);
  }

  // hue 0-360, saturation 0-100, intensity 0–1000.
  async setTelinkHSI(dst: number, hue: number, saturation: number, intensity: number): Promise<void> {
    await this.send(dst, OP.TELINK_CMD, telink.hsi(hue, saturation, intensity), 3);
  }

  // Status-request: makes the fixture broadcast its current state so the
  // ESP32 bridge / desktop app re-sync immediately instead of waiting for a
  // poll. Fire-and-forget (single send) — a missed one is caught by the next
  // poll. Mirrors the firmware's schedule_refresh().
  async statusRequest(dst: number): Promise<void> {
    await this.send(dst, OP.TELINK_CMD, telink.statusRequest(), 1);
  }

  async setBrightness(dst: number, percent: number): Promise<void> {
    await this.setTelinkBrightness(dst, Math.round(percent * 10));
  }

  async setCCT(dst: number, brightnessPercent: number, kelvin: number, gm = 0): Promise<void> {
    await this.setTelinkCCT(dst, kelvin, Math.round(brightnessPercent * 10), gm);
  }

  async setHSL(dst: number, brightnessPercent: number, hueDeg: number, satPercent: number): Promise<void> {
    await this.setTelinkHSI(dst, hueDeg, satPercent, Math.round(brightnessPercent * 10));
  }

  async disconnect(): Promise<void> {
    if (this.peripheral) {
      await this.peripheral.disconnectAsync();
      console.log("Disconnected");
    }
  }
}

