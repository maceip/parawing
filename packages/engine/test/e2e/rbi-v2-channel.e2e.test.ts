// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { expect, test } from "vitest";
import {
  decodeRbiV2Packet,
  encodeCreditGrantPacket,
  encodeDatagramPacket,
  encodeReattachWithTileHashesPacket,
  extractKsc2TileMetadata,
  RbiV2PacketKind,
} from "../../src/rbi-v2.ts";
import { upgradedSocket, type WorkerdWebSocket } from "./connect";
import { engine } from "./harness";

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

class Ksc2SummaryReader {
  readonly view: DataView;
  readonly bytes: Uint8Array;
  pos = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  skip(n: number): void {
    if (n < 0 || this.pos + n > this.bytes.byteLength) {
      throw new Error(`KSC2 out of bounds skip(${n}) at ${this.pos}`);
    }
    this.pos += n;
  }

  u8(): number {
    this.skip(1);
    return this.bytes[this.pos - 1]!;
  }

  u32(): number {
    this.skip(4);
    return this.view.getUint32(this.pos - 4, true);
  }

  u64(): bigint {
    this.skip(8);
    return this.view.getBigUint64(this.pos - 8, true);
  }

  f32(): number {
    this.skip(4);
    return this.view.getFloat32(this.pos - 4, true);
  }

  str(): string {
    const len = this.u32();
    const slice = this.bytes.subarray(this.pos, this.pos + len);
    this.skip(len);
    return new TextDecoder().decode(slice);
  }

  skipBlob(): void {
    this.skip(this.u32());
  }
}

function skipKsc2LayerKind(r: Ksc2SummaryReader): void {
  const tag = r.u8();
  if (tag === 0) return;
  if (tag === 1) {
    r.skip(16);
    return;
  }
  r.skip(32);
  for (let i = 0; i < 4; i++) {
    if (r.u8() !== 0) r.skip(4);
  }
}

function skipKsc2AnimCurve(r: Ksc2SummaryReader): void {
  r.skip(22);
  const kfCount = r.u32();
  for (let k = 0; k < kfCount; k++) {
    r.skip(4);
    const vtag = r.u8();
    r.skip(vtag === 0 ? 4 : 24);
    if (r.u8() === 2) r.skip(16);
  }
}

function skipKsc2Layers(r: Ksc2SummaryReader): void {
  const count = r.u32();
  for (let i = 0; i < count; i++) {
    r.skip(16);
    skipKsc2LayerKind(r);
    r.skip(48);
    const animCount = r.u32();
    for (let a = 0; a < animCount; a++) skipKsc2AnimCurve(r);
    r.skip(4);
    r.skip(r.u32() * 32);
    r.skip(r.u32() * 8);
  }
}

function skipKsc2Tiles(r: Ksc2SummaryReader): void {
  const tileCount = r.u32();
  for (let i = 0; i < tileCount; i++) {
    r.skip(16);
    r.skipBlob();
    const runCount = r.u32();
    for (let j = 0; j < runCount; j++) {
      r.skip(8);
      r.skipBlob();
      r.skip(29);
      r.skip(r.u32() * 32);
    }
    const hitCount = r.u32();
    for (let j = 0; j < hitCount; j++) {
      r.skip(33);
      if (r.u8() !== 0) r.skipBlob();
      r.skip(2);
    }
  }
}

interface Ksc2Inspection {
  ackedInputSeq: number;
  scrollNodes: Array<{ nodeId: bigint; serverDriven: boolean; reason: number }>;
  handlerRegions: Array<{ w: number; h: number; scrollNodeId: bigint; nonPassive: boolean }>;
  editableSpecs: Array<{
    nodeId: bigint;
    fieldKey: string;
    authText: string;
    isPassword: boolean;
  }>;
}

function decodeKsc2Inspection(frameBytes: Uint8Array): Ksc2Inspection {
  const r = new Ksc2SummaryReader(frameBytes);
  const magic = String.fromCharCode(r.u8(), r.u8(), r.u8(), r.u8());
  if (magic !== "KSC2" || r.u32() !== 1) throw new Error(`unexpected KSC2 header: ${magic}`);
  r.u32(); // acked_scroll_seq
  const ackedInputSeq = r.u32();
  r.skip(8); // viewport_w, viewport_h

  const snCount = r.u32();
  const scrollNodes: Ksc2Inspection["scrollNodes"] = [];
  for (let i = 0; i < snCount; i++) {
    const nodeId = r.u64();
    r.skip(40);
    r.skip(r.u32() * 4);
    r.skip(r.u32() * 4);
    r.skip(2); // overscroll_x, overscroll_y
    scrollNodes.push({ nodeId, serverDriven: r.u8() !== 0, reason: r.u8() });
  }
  skipKsc2Layers(r);
  skipKsc2Tiles(r);

  const regCount = r.u32();
  const handlerRegions: Ksc2Inspection["handlerRegions"] = [];
  for (let i = 0; i < regCount; i++) {
    r.skip(8);
    const w = r.f32();
    const h = r.f32();
    const scrollNodeId = r.u64();
    r.u8();
    handlerRegions.push({ w, h, scrollNodeId, nonPassive: r.u8() !== 0 });
  }

  const specCount = r.u32();
  const editableSpecs: Ksc2Inspection["editableSpecs"] = [];
  for (let i = 0; i < specCount; i++) {
    const nodeId = r.u64();
    r.u64();
    const fieldKey = r.str();
    const authText = r.str();
    r.skip(16);
    const isPassword = r.u8() !== 0;
    r.skip(40);
    r.skipBlob();
    r.skip(r.u32() * 6);
    r.skip(r.u32() * 2);
    editableSpecs.push({ nodeId, fieldKey, authText, isPassword });
  }
  return { ackedInputSeq, scrollNodes, handlerRegions, editableSpecs };
}

async function toBytes(data: unknown): Promise<Uint8Array> {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
  throw new Error(
    `unexpected ws payload type: ${typeof data} (${Object.prototype.toString.call(data)})`,
  );
}

interface CdpEventRecord {
  method: string;
  params?: Record<string, unknown>;
  sessionId?: string;
}

interface CdpClient {
  events: CdpEventRecord[];
  send(
    method: string,
    params?: Record<string, unknown>,
    sessionId?: string,
  ): Promise<Record<string, unknown>>;
  waitEvent(
    predicate: (ev: CdpEventRecord) => boolean,
    timeoutMs?: number,
    label?: string,
  ): Promise<CdpEventRecord>;
  close(): void;
}

function createCdpClient(ws: WorkerdWebSocket): CdpClient {
  ws.accept();
  let nextId = 0;
  const events: CdpEventRecord[] = [];
  const waiters: Array<(ev: CdpEventRecord) => void> = [];
  const pending = new Map<number, (val: Record<string, unknown>) => void>();
  ws.addEventListener("message", (event: { data: string | ArrayBuffer }) => {
    if (typeof event.data !== "string") return;
    const msg = JSON.parse(event.data) as {
      id?: number;
      method?: string;
      params?: Record<string, unknown>;
      sessionId?: string;
      result?: Record<string, unknown>;
      error?: { message: string };
    };
    if (msg.id === undefined) {
      if (typeof msg.method === "string") {
        const rec: CdpEventRecord = {
          method: msg.method,
          params: msg.params,
          sessionId: msg.sessionId,
        };
        events.push(rec);
        for (const w of waiters) w(rec);
      }
      return;
    }
    const resolve = pending.get(msg.id);
    if (!resolve) return;
    pending.delete(msg.id);
    resolve(msg.error ? { error: msg.error.message } : (msg.result ?? {}));
  });
  return {
    events,
    send(method, params = {}, sessionId) {
      const id = ++nextId;
      return new Promise((resolve) => {
        pending.set(id, resolve);
        ws.send(JSON.stringify({ id, method, params, sessionId }));
      });
    },
    waitEvent(predicate, timeoutMs = 8_000, label = "predicate") {
      const existing = events.find(predicate);
      if (existing) return Promise.resolve(existing);
      return new Promise((resolve, reject) => {
        const onEvent = (ev: CdpEventRecord) => {
          if (!predicate(ev)) return;
          clearTimeout(timer);
          const idx = waiters.indexOf(onEvent);
          if (idx >= 0) waiters.splice(idx, 1);
          resolve(ev);
        };
        const timer = setTimeout(() => {
          const idx = waiters.indexOf(onEvent);
          if (idx >= 0) waiters.splice(idx, 1);
          const seen = events.map((e) => e.method).join(", ");
          reject(new Error(`timed out waiting for CDP event (${label}); seen=[${seen}]`));
        }, timeoutMs);
        waiters.push(onEvent);
      });
    },
    close() {
      ws.close();
    },
  };
}

function waitBinaryPacket(
  ws: WorkerdWebSocket,
  predicate: (pkt: ReturnType<typeof decodeRbiV2Packet>) => boolean,
  timeoutMs = 8_000,
): Promise<ReturnType<typeof decodeRbiV2Packet>> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.removeEventListener("message", onMsg);
      reject(new Error("timed out waiting for S7 KSV2 packet"));
    }, timeoutMs);
    const onMsg = (ev: { data: unknown }) => {
      if (typeof ev.data === "string") return;
      void toBytes(ev.data)
        .then((bytes) => {
          const decoded = decodeRbiV2Packet(bytes);
          if (!predicate(decoded)) return;
          clearTimeout(timer);
          ws.removeEventListener("message", onMsg);
          resolve(decoded);
        })
        .catch((err: unknown) => {
          clearTimeout(timer);
          ws.removeEventListener("message", onMsg);
          reject(err instanceof Error ? err : new Error(String(err)));
        });
    };
    ws.addEventListener("message", onMsg);
  });
}

const TEST_HTML = [
  "<!doctype html><html><body style='margin:0;height:1600px'>",
  "<div style='position:fixed;top:0;left:0;width:800px;height:40px;background:#123456'>Fixed</div>",
  "<div style='position:sticky;top:10px;width:120px;height:30px;background:#abcdef'>Sticky</div>",
  "<div id='trap' style='position:absolute;top:50px;left:10px;width:160px;height:90px;background:#ddeeff'>Trap</div>",
  "<div style='position:absolute;top:300px;left:0;width:800px;height:60px;background:#00aa55'>BandA</div>",
  "<div style='position:absolute;top:540px;left:300px;width:240px;height:40px;background:#aa5500'>BandB</div>",
  "<input id='usr' name='user' type='text' style='position:absolute;top:160px;left:10px;width:180px;height:28px' />",
  "<input id='pwd' name='password' type='password' style='position:absolute;top:200px;left:10px;width:180px;height:28px' />",
  "<script>",
  "document.getElementById('trap').addEventListener('wheel', function(e) { e.preventDefault(); }, { passive: false });",
  "</script></body></html>",
].join("");

test("S7 /rbi/ws binary channel, KSC2 multi-tile scenes, handler regions, and 8.8 input journal", async () => {
  expect((await engine.fetch("https://ks.invalid/rbi/ws")).status).toBe(404);
  expect(
    (await engine.fetch("https://ks.invalid/rbi/ws", { headers: { Upgrade: "websocket" } })).status,
  ).toBe(404);

  const cdpResp = await engine.fetch("https://ks.invalid/devtools/browser", {
    headers: { Upgrade: "websocket" },
  });
  const cdpWs = upgradedSocket(cdpResp);
  if (!cdpWs) throw new Error(`CDP upgrade failed: ${cdpResp.status}`);
  const cdp = createCdpClient(cdpWs);
  let v2Ws: WorkerdWebSocket | null = null;
  let sessionIdForCleanup: string | undefined;

  try {
    const targets = (await cdp.send("Target.getTargets")) as {
      targetInfos: Array<{ targetId: string; type: string }>;
    };
    const pageId = targets.targetInfos.find((t) => t.type === "page")?.targetId;
    if (!pageId) throw new Error("missing page target");
    const attached = await cdp.send("Target.attachToTarget", { targetId: pageId, flatten: true });
    const sessionId = String(attached.sessionId ?? "");
    sessionIdForCleanup = sessionId;

    await cdp.send(
      "Emulation.setDeviceMetricsOverride",
      { width: 800, height: 600, deviceScaleFactor: 1, mobile: false },
      sessionId,
    );
    await cdp.send(
      "Page.navigate",
      { url: `data:text/html;charset=utf-8,${encodeURIComponent(TEST_HTML)}` },
      sessionId,
    );

    const handlerRes = (await cdp.send("Parawing.getHandlerRegions", {}, sessionId)) as {
      regions: Array<{
        nonPassive: boolean;
        width: number;
        height: number;
        coversScrollNode: boolean;
      }>;
    };
    expect(
      handlerRes.regions.some((r) => r.nonPassive && r.width >= 150 && !r.coversScrollNode),
    ).toBe(true);

    const rec = (await cdp.send("Parawing.recordSceneV2", {}, sessionId)) as {
      frameB64: string;
      handlerRegions: unknown[];
    };
    const rawKsc2 = fromBase64(rec.frameB64);
    expect(String.fromCharCode(...rawKsc2.subarray(0, 4))).toBe("KSC2");
    expect(rawKsc2.byteLength).toBeGreaterThan(200);
    expect(rec.handlerRegions.length).toBeGreaterThanOrEqual(1);
    const ksc2Trap = decodeKsc2Inspection(rawKsc2);
    expect(ksc2Trap.scrollNodes[0]?.nodeId).toBe(0n);
    expect(ksc2Trap.scrollNodes[0]?.serverDriven).toBe(false);
    expect(ksc2Trap.scrollNodes[0]?.reason).toBe(0);
    expect(
      ksc2Trap.handlerRegions.some(
        (r) => r.nonPassive && r.scrollNodeId === 0n && r.w >= 150 && r.h >= 85,
      ),
    ).toBe(true);

    const startV2 = (await cdp.send(
      "Parawing.startSceneStreamV2",
      { width: 800, height: 600, fps: 30 },
      sessionId,
    )) as { wsPath: string; token: string };
    expect(startV2.wsPath).toBe(`/rbi/ws?token=${startV2.token}`);

    const wsResp = await engine.fetch(`https://ks.invalid${startV2.wsPath}`, {
      headers: { Upgrade: "websocket" },
    });
    expect(wsResp.status).toBe(101);
    v2Ws = upgradedSocket(wsResp);
    if (!v2Ws) throw new Error("missing S7 WebSocket");

    const initialPktPromise = waitBinaryPacket(
      v2Ws,
      (p) => p.kind === RbiV2PacketKind.ReliableFrame,
    );
    v2Ws.accept();
    const sendBin = (bytes: Uint8Array) => {
      const buf = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(buf).set(bytes);
      v2Ws?.send(buf);
    };
    sendBin(encodeCreditGrantPacket(2, 0));

    const firstFrame = await initialPktPromise;
    expect(firstFrame.kind).toBe(RbiV2PacketKind.ReliableFrame);
    if (firstFrame.kind !== RbiV2PacketKind.ReliableFrame) {
      throw new Error("expected ReliableFrame");
    }
    expect(String.fromCharCode(...firstFrame.payload.subarray(0, 4))).toBe("KSC2");
    const firstMeta = extractKsc2TileMetadata(firstFrame.payload);
    expect(firstFrame.tileCount).toBeGreaterThanOrEqual(2);
    expect(firstFrame.tileCount).toBe(firstMeta.tileCount);

    // CreditGrant acknowledges firstFrame hashes; the subsequent redraw drops cached tiles.
    const nextDeltaPromise = waitBinaryPacket(
      v2Ws,
      (p) => p.kind === RbiV2PacketKind.ReliableFrame && p.frameSeq > firstFrame.frameSeq,
    );
    sendBin(encodeCreditGrantPacket(2, firstFrame.frameSeq));
    await new Promise((r) => setTimeout(r, 30));
    await cdp.send(
      "Runtime.evaluate",
      {
        expression:
          "var t=document.getElementById('trap');t.textContent='Updated';t.style.backgroundColor='#336699';",
      },
      sessionId,
    );
    const secondFrame = await nextDeltaPromise;
    if (secondFrame.kind !== RbiV2PacketKind.ReliableFrame) {
      throw new Error("expected delta ReliableFrame");
    }
    const secondMeta = extractKsc2TileMetadata(secondFrame.payload);
    const firstHashSet = new Set(firstMeta.tileHashes);
    const repeatedHashes = secondMeta.tileHashes.filter((h) => firstHashSet.has(h)).length;
    expect(repeatedHashes).toBe(0);
    expect(secondFrame.tileCount).toBe(secondMeta.tileCount);
    expect(secondFrame.tileCount).toBeLessThan(firstFrame.tileCount);
    expect(secondFrame.payload.byteLength).toBeLessThan(firstFrame.payload.byteLength);

    const resyncPromise = waitBinaryPacket(v2Ws, (p) => p.kind === RbiV2PacketKind.DeltaResyncAck);
    sendBin(
      encodeDatagramPacket({
        kind: "scroll",
        seq: 1,
        scrollNodeId: 0n,
        x: 0,
        y: 240,
        velX: 0,
        velY: 0,
      }),
    );
    sendBin(
      encodeReattachWithTileHashesPacket(1, [123456n], { x: 0, y: 240, w: 800, h: 600 }, 0, 0),
    );
    const resyncPkt = await resyncPromise;
    expect(resyncPkt.kind).toBe(RbiV2PacketKind.DeltaResyncAck);

    const scrolled = (await cdp.send("Parawing.recordSceneV2", {}, sessionId)) as {
      scrollY: number;
    };
    expect(scrolled.scrollY).toBe(240);

    await cdp.send(
      "Runtime.evaluate",
      { expression: "document.getElementById('usr').focus()" },
      sessionId,
    );
    await cdp.send("Input.insertText", { text: "alice" }, sessionId);

    await cdp.send(
      "Runtime.evaluate",
      { expression: "document.getElementById('pwd').focus()" },
      sessionId,
    );
    await cdp.send("Input.insertText", { text: "supersecret" }, sessionId);

    const jState = (await cdp.send(
      "Parawing.getInputJournalState",
      { includeEncryptedSnapshot: true },
      sessionId,
    )) as {
      size: number;
      encryptedCount: number;
      nextInputSeq: number;
      lastRejectionReason?: string;
    };
    expect(jState.size).toBe(1);
    expect(jState.encryptedCount).toBe(1);
    expect(jState.lastRejectionReason).toBe("password-field");

    await cdp.send(
      "Runtime.evaluate",
      { expression: "document.getElementById('usr').value = ''" },
      sessionId,
    );
    const replayState = (await cdp.send(
      "Parawing.getInputJournalState",
      { replay: true },
      sessionId,
    )) as { replayedCount: number };
    expect(replayState.replayedCount).toBe(1);

    const restoredVal = (await cdp.send(
      "Runtime.evaluate",
      { expression: "document.getElementById('usr').value" },
      sessionId,
    )) as { result?: { value?: string } };
    expect(restoredVal.result?.value).toBe("alice");

    await cdp.send("Parawing.stopSceneStreamV2", {}, sessionId);

    await cdp.send("Page.navigate", { url: "about:blank" }, sessionId);
    const afterNav = (await cdp.send("Parawing.getInputJournalState", {}, sessionId)) as {
      size: number;
    };
    expect(afterNav.size).toBe(0);
  } finally {
    try {
      await cdp.send("Parawing.stopSceneStreamV2", {}, sessionIdForCleanup);
    } catch {}
    if (v2Ws) {
      await new Promise<void>((resolve) => {
        if (v2Ws!.readyState >= 2) {
          resolve();
          return;
        }
        const done = () => resolve();
        v2Ws!.addEventListener("close", done, { once: true });
        try {
          v2Ws!.close();
        } catch {
          resolve();
        }
        setTimeout(done, 500);
      });
    }
    try {
      if (sessionIdForCleanup) {
        const targets = (await cdp.send("Target.getTargets")) as {
          targetInfos?: Array<{ targetId: string; type: string }>;
        };
        const pageTarget = targets.targetInfos?.find((t) => t.type === "page");
        if (pageTarget) {
          await cdp.send("Target.closeTarget", { targetId: pageTarget.targetId });
        }
      }
    } catch {}
    await new Promise<void>((resolve) => {
      if (cdpWs.readyState >= 2) {
        resolve();
        return;
      }
      cdpWs.addEventListener("close", () => resolve(), { once: true });
      cdp.close();
      setTimeout(resolve, 500);
    });
  }
});

test("4A & 4B: document/window handlers mark server_driven and _parawingInputSeq advances KSC2 ack", async () => {
  const cdpResp = await engine.fetch("https://ks.invalid/devtools/browser", {
    headers: { Upgrade: "websocket" },
  });
  const cdpWs = upgradedSocket(cdpResp);
  if (!cdpWs) throw new Error(`CDP upgrade failed: ${cdpResp.status}`);
  const cdp = createCdpClient(cdpWs);
  let pageIdForCleanup: string | undefined;

  try {
    const targets = (await cdp.send("Target.getTargets")) as {
      targetInfos?: Array<{ targetId: string; type: string }>;
    };
    const pageId = targets.targetInfos?.find((t) => t.type === "page")?.targetId;
    if (!pageId) throw new Error("missing initial page target");
    pageIdForCleanup = pageId;
    const attached = await cdp.send("Target.attachToTarget", { targetId: pageId, flatten: true });
    const sessionId = String(attached.sessionId ?? "");
    await cdp.send(
      "Emulation.setDeviceMetricsOverride",
      { width: 800, height: 600, deviceScaleFactor: 1, mobile: false },
      sessionId,
    );

    const docListenerHtml = [
      "<!doctype html><html><body style='margin:0;height:1600px'>",
      "<script>document.addEventListener('wheel',function(e){e.preventDefault();},{passive:false});</script>",
      "</body></html>",
    ].join("");
    await cdp.send(
      "Page.navigate",
      { url: `data:text/html;charset=utf-8,${encodeURIComponent(docListenerHtml)}` },
      sessionId,
    );
    const docRec = (await cdp.send("Parawing.recordSceneV2", { targetId: pageId }, sessionId)) as {
      frameB64: string;
    };
    const docKsc2 = decodeKsc2Inspection(fromBase64(docRec.frameB64));
    expect(docKsc2.scrollNodes[0]?.nodeId).toBe(0n);
    expect(docKsc2.scrollNodes[0]?.serverDriven).toBe(true);
    expect(docKsc2.scrollNodes[0]?.reason).toBe(1);

    const winListenerHtml = [
      "<!doctype html><html><body style='margin:0;height:1600px'>",
      "<script>window.addEventListener('wheel',function(e){e.preventDefault();},{passive:false});</script>",
      "</body></html>",
    ].join("");
    await cdp.send(
      "Page.navigate",
      { url: `data:text/html;charset=utf-8,${encodeURIComponent(winListenerHtml)}` },
      sessionId,
    );
    const winRec = (await cdp.send("Parawing.recordSceneV2", { targetId: pageId }, sessionId)) as {
      frameB64: string;
    };
    const winKsc2 = decodeKsc2Inspection(fromBase64(winRec.frameB64));
    expect(winKsc2.scrollNodes[0]?.serverDriven).toBe(true);
    expect(winKsc2.scrollNodes[0]?.reason).toBe(1);

    const inputHtml = [
      "<!doctype html><html><body style='margin:0'>",
      "<input id='upper' type='text' style='width:200px;height:30px' />",
      "<input id='trapkey' type='text' style='width:200px;height:30px' />",
      "<input id='pwd' type='password' style='width:200px;height:30px' />",
      "<script>",
      "document.getElementById('upper').addEventListener('input',function(){this.value=this.value.toUpperCase();});",
      "document.getElementById('trapkey').addEventListener('keydown',function(e){e.preventDefault();});",
      "</script></body></html>",
    ].join("");
    await cdp.send(
      "Page.navigate",
      { url: `data:text/html;charset=utf-8,${encodeURIComponent(inputHtml)}` },
      sessionId,
    );

    await cdp.send(
      "Runtime.evaluate",
      { expression: "document.getElementById('upper').focus()" },
      sessionId,
    );
    await cdp.send(
      "Input.dispatchKeyEvent",
      {
        type: "rawKeyDown",
        key: "a",
        code: "KeyA",
        windowsVirtualKeyCode: 65,
        text: "a",
        modifiers: 0,
        _parawingInputSeq: 1,
      },
      sessionId,
    );
    const k1Rec = (await cdp.send("Parawing.recordSceneV2", { targetId: pageId }, sessionId)) as {
      frameB64: string;
    };
    const k1 = decodeKsc2Inspection(fromBase64(k1Rec.frameB64));
    expect(k1.ackedInputSeq).toBe(1);
    expect(k1.editableSpecs.find((s) => s.fieldKey.includes("upper"))?.authText).toBe("A");

    await cdp.send(
      "Input.dispatchKeyEvent",
      {
        type: "rawKeyDown",
        key: "b",
        code: "KeyB",
        windowsVirtualKeyCode: 66,
        text: "b",
        modifiers: 0,
        _parawingInputSeq: 2,
      },
      sessionId,
    );
    const k2Rec = (await cdp.send("Parawing.recordSceneV2", { targetId: pageId }, sessionId)) as {
      frameB64: string;
    };
    const k2 = decodeKsc2Inspection(fromBase64(k2Rec.frameB64));
    expect(k2.ackedInputSeq).toBe(2);
    expect(k2.editableSpecs.find((s) => s.fieldKey.includes("upper"))?.authText).toBe("AB");

    // Keydown preventDefault skips journal capture, yet acknowledgeClientInputSeq catches up.
    await cdp.send(
      "Runtime.evaluate",
      { expression: "document.getElementById('trapkey').focus()" },
      sessionId,
    );
    await cdp.send(
      "Input.dispatchKeyEvent",
      {
        type: "rawKeyDown",
        key: "z",
        code: "KeyZ",
        windowsVirtualKeyCode: 90,
        text: "z",
        modifiers: 0,
        _parawingInputSeq: 3,
      },
      sessionId,
    );
    const k3Rec = (await cdp.send("Parawing.recordSceneV2", { targetId: pageId }, sessionId)) as {
      frameB64: string;
    };
    const k3 = decodeKsc2Inspection(fromBase64(k3Rec.frameB64));
    expect(k3.ackedInputSeq).toBe(3);

    // Password input advances ackedInputSeq while redacting authText to "".
    await cdp.send(
      "Runtime.evaluate",
      { expression: "document.getElementById('pwd').focus()" },
      sessionId,
    );
    await cdp.send(
      "Input.dispatchKeyEvent",
      {
        type: "rawKeyDown",
        key: "s",
        code: "KeyS",
        windowsVirtualKeyCode: 83,
        text: "s",
        modifiers: 0,
        _parawingInputSeq: 4,
      },
      sessionId,
    );
    const k4Rec = (await cdp.send("Parawing.recordSceneV2", { targetId: pageId }, sessionId)) as {
      frameB64: string;
    };
    const k4 = decodeKsc2Inspection(fromBase64(k4Rec.frameB64));
    expect(k4.ackedInputSeq).toBe(4);
    const pwdSpec = k4.editableSpecs.find((s) => s.fieldKey.includes("pwd"));
    expect(pwdSpec?.isPassword).toBe(true);
    expect(pwdSpec?.authText).toBe("");
  } finally {
    try {
      if (pageIdForCleanup) {
        await cdp.send("Target.closeTarget", { targetId: pageIdForCleanup });
      }
    } catch {}
    await new Promise<void>((resolve) => {
      if (cdpWs.readyState >= 2) {
        resolve();
        return;
      }
      cdpWs.addEventListener("close", () => resolve(), { once: true });
      cdp.close();
      setTimeout(resolve, 500);
    });
  }
});

function waitTextReply(
  ws: WorkerdWebSocket,
  predicate: (msg: Record<string, unknown>) => boolean,
  timeoutMs = 8_000,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.removeEventListener("message", onMsg);
      reject(new Error("timed out waiting for /rbi/ws text reply"));
    }, timeoutMs);
    const onMsg = (ev: { data: unknown }) => {
      if (typeof ev.data !== "string") return;
      try {
        const parsed = JSON.parse(ev.data) as Record<string, unknown>;
        if (!predicate(parsed)) return;
        clearTimeout(timer);
        ws.removeEventListener("message", onMsg);
        resolve(parsed);
      } catch {}
    };
    ws.addEventListener("message", onMsg);
  });
}

async function openCdpClient(query: string): Promise<{ ws: WorkerdWebSocket; client: CdpClient }> {
  const resp = await engine.fetch(`https://ks.invalid/devtools/browser${query}`, {
    headers: { Upgrade: "websocket" },
  });
  const ws = upgradedSocket(resp);
  if (!ws) throw new Error(`CDP upgrade failed (${resp.status}) for ${query}`);
  return { ws, client: createCdpClient(ws) };
}

async function closeSocketCleanly(ws: WorkerdWebSocket | null): Promise<void> {
  if (!ws || ws.readyState >= 2) return;
  await new Promise<void>((resolve) => {
    ws.addEventListener("close", () => resolve(), { once: true });
    ws.close();
    setTimeout(resolve, 400);
  });
}

test("cross-phase warm reconnect, Tier 1 GET-only + journal delta replay, and human takeover over ViewerChannelV2", async () => {
  const ksSessionId = `e2e-p34-${crypto.randomUUID()}`;
  const ksUserId = "e2e-user";
  const formBody = [
    "<form id='checkout' method='POST' action='/__fixtures/form-echo'>",
    "<input id='draft' name='note' type='text' style='position:absolute;top:20px;left:20px;width:220px;height:28px' />",
    "<input id='pwd' name='password' type='password' autocomplete='current-password' style='position:absolute;top:60px;left:20px;width:220px;height:28px' />",
    "<input id='otp' name='otp_code' type='text' autocomplete='one-time-code' style='position:absolute;top:100px;left:20px;width:220px;height:28px' />",
    "<input id='cc' name='cardnum' type='text' autocomplete='cc-number' style='position:absolute;top:140px;left:20px;width:220px;height:28px' />",
    "</form>",
  ].join("");
  const safeGetUrl = `https://ks.invalid/__fixtures/policy-doc.html?body=${encodeURIComponent(formBody)}`;

  let cdp1: { ws: WorkerdWebSocket; client: CdpClient } | null = null;
  let cdpWarm: { ws: WorkerdWebSocket; client: CdpClient } | null = null;
  let cdpRestored: { ws: WorkerdWebSocket; client: CdpClient } | null = null;
  let cdpViewer: { ws: WorkerdWebSocket; client: CdpClient } | null = null;
  let v2Ws: WorkerdWebSocket | null = null;

  try {
    cdp1 = await openCdpClient(
      `?ksSessionId=${encodeURIComponent(ksSessionId)}&ksUserId=${encodeURIComponent(ksUserId)}`,
    );
    const targets1 = (await cdp1.client.send("Target.getTargets")) as {
      targetInfos: Array<{ targetId: string; type: string }>;
    };
    const pageId = targets1.targetInfos.find((t) => t.type === "page")?.targetId;
    if (!pageId) throw new Error("missing initial page target");
    const att1 = await cdp1.client.send("Target.attachToTarget", {
      targetId: pageId,
      flatten: true,
    });
    const sid1 = String(att1.sessionId ?? "");

    await cdp1.client.send(
      "Emulation.setDeviceMetricsOverride",
      { width: 800, height: 600, deviceScaleFactor: 1, mobile: false },
      sid1,
    );
    await cdp1.client.send("Page.navigate", { url: safeGetUrl }, sid1);
    await cdp1.client.send(
      "Runtime.evaluate",
      { expression: "window.__warmMarker = 'before-detach'" },
      sid1,
    );

    // In stateless workerd each HTTP request owns its IoContext, so disconnect checkpoints and
    // resumes via Tier 1 GET-only restore. True warm Tier 0 is verified in deno-host-e2e.
    await closeSocketCleanly(cdp1.ws);
    cdp1 = null;

    cdpWarm = await openCdpClient(
      `?ksSessionId=${encodeURIComponent(ksSessionId)}&ksUserId=${encodeURIComponent(ksUserId)}`,
    );
    await cdpWarm.client.waitEvent(
      (ev) =>
        ev.method === "Parawing.sessionResumed" && (ev.params as { tier?: number })?.tier === 1,
    );
    const warmAtt = await cdpWarm.client.send("Target.attachToTarget", {
      targetId: pageId,
      flatten: true,
    });
    const warmSid = String(warmAtt.sessionId ?? "");
    const warmMarker = (await cdpWarm.client.send(
      "Runtime.evaluate",
      { expression: "window.__warmMarker ?? null" },
      warmSid,
    )) as { result?: { value?: unknown } };
    expect(warmMarker.result?.value).toBeNull();

    // Capture seq=1, acknowledge checkpointSeq=1, then type unacked seq=2 delta + sensitive fields.
    await cdpWarm.client.send(
      "Runtime.evaluate",
      { expression: "document.getElementById('draft').focus()" },
      warmSid,
    );
    await cdpWarm.client.send(
      "Input.dispatchKeyEvent",
      {
        type: "rawKeyDown",
        key: "A",
        code: "KeyA",
        windowsVirtualKeyCode: 65,
        text: "A",
        modifiers: 0,
      },
      warmSid,
    );
    const ackRes = (await cdpWarm.client.send(
      "Parawing.getInputJournalState",
      { acknowledgeSeq: 1 },
      warmSid,
    )) as { ackedInputSeq?: number };
    expect(ackRes.ackedInputSeq).toBe(1);

    await cdpWarm.client.send(
      "Input.dispatchKeyEvent",
      {
        type: "rawKeyDown",
        key: "B",
        code: "KeyB",
        windowsVirtualKeyCode: 66,
        text: "B",
        modifiers: 0,
      },
      warmSid,
    );
    for (const [id, ch] of [
      ["pwd", "s"],
      ["otp", "7"],
      ["cc", "4"],
    ] as const) {
      await cdpWarm.client.send(
        "Runtime.evaluate",
        { expression: `document.getElementById('${id}').focus()` },
        warmSid,
      );
      await cdpWarm.client.send(
        "Input.dispatchKeyEvent",
        {
          type: "rawKeyDown",
          key: ch,
          code: "KeyX",
          windowsVirtualKeyCode: ch.charCodeAt(0),
          text: ch,
          modifiers: 0,
        },
        warmSid,
      );
    }

    const journalState = (await cdpWarm.client.send(
      "Parawing.getInputJournalState",
      {},
      warmSid,
    )) as { size?: number };
    expect(journalState.size).toBe(1);

    // Suspend closes the runtime isolate so reconnect runs Tier 1 GET-only + delta replay.
    await cdpWarm.client.send("Parawing.suspendSession", { reason: "suspend" });
    await closeSocketCleanly(cdpWarm.ws);
    cdpWarm = null;

    cdpRestored = await openCdpClient(
      `?ksSessionId=${encodeURIComponent(ksSessionId)}&ksUserId=${encodeURIComponent(ksUserId)}`,
    );
    const restoredEv = await cdpRestored.client.waitEvent(
      (ev) => ev.method === "Parawing.sessionRestored",
    );
    expect(
      (restoredEv.params as { replayedClientInputSeqs?: number[] })?.replayedClientInputSeqs,
    ).toEqual([2]);
    await cdpRestored.client.waitEvent(
      (ev) =>
        ev.method === "Parawing.sessionResumed" && (ev.params as { tier?: number })?.tier === 1,
    );
    const att2 = await cdpRestored.client.send("Target.attachToTarget", {
      targetId: pageId,
      flatten: true,
    });
    const sid2 = String(att2.sessionId ?? "");

    const postRestoreValues = (await cdpRestored.client.send(
      "Runtime.evaluate",
      {
        expression:
          "({ draft: document.getElementById('draft').value, pwd: document.getElementById('pwd').value, otp: document.getElementById('otp').value, cc: document.getElementById('cc').value, marker: window.__warmMarker ?? null })",
        returnByValue: true,
      },
      sid2,
    )) as { result?: { value?: Record<string, unknown> } };
    expect(postRestoreValues.result?.value).toEqual({
      draft: "AB",
      pwd: "",
      otp: "",
      cc: "",
      marker: null,
    });

    // Wire ControllerLease human takeover over ViewerChannelV2 (/rbi/ws + viewer CDP session).
    await cdpRestored.client.send("Runtime.enable", {}, sid2);
    await cdpRestored.client.send("Network.enable", {}, sid2);
    await cdpRestored.client.send(
      "Page.startScreencast",
      { format: "png", everyNthFrame: 1 },
      sid2,
    );
    const v2Start = (await cdpRestored.client.send(
      "Parawing.startSceneStreamV2",
      { width: 800, height: 600, fps: 30 },
      sid2,
    )) as { wsPath?: string };
    const v2Resp = await engine.fetch(`https://ks.invalid${v2Start.wsPath}`, {
      headers: { Upgrade: "websocket" },
    });
    v2Ws = upgradedSocket(v2Resp);
    if (!v2Ws) throw new Error("missing /rbi/ws upgrade");
    v2Ws.accept();
    const sendV2Bin = (bytes: Uint8Array) => {
      const buf = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(buf).set(bytes);
      v2Ws?.send(buf);
    };
    const initSceneP = waitBinaryPacket(v2Ws, (pkt) => pkt.kind === RbiV2PacketKind.ReliableFrame);
    sendV2Bin(encodeCreditGrantPacket(8, 0));
    await initSceneP;

    cdpViewer = await openCdpClient(
      `?ksSessionId=${encodeURIComponent(ksSessionId)}&ksUserId=${encodeURIComponent(ksUserId)}&ksRole=viewer`,
    );
    await cdpViewer.client.waitEvent((ev) => ev.method === "Parawing.sessionAttached");
    const leaseReq = (await cdpViewer.client.send("Parawing.requestControllerLease", {
      targetId: pageId,
      requesterId: "human-viewer",
      reason: "manual-check",
    })) as { lease?: { leaseId?: string } };
    const leaseId = String(leaseReq.lease?.leaseId ?? "");
    expect(leaseId.startsWith("ctrl-")).toBe(true);

    // Unapproved /rbi/ws text input, pointer click, and viewer scroll must all be rejected.
    await cdpRestored.client.send(
      "Runtime.evaluate",
      {
        expression:
          "document.body.style.minHeight='1600px'; document.getElementById('pwd').focus();",
      },
      sid2,
    );
    const unleasedTextP = waitTextReply(v2Ws, (m) => m["id"] === 97);
    v2Ws.send(JSON.stringify({ id: 97, type: "insertText", text: "nope" }));
    const unleasedText = await unleasedTextP;
    expect(unleasedText["ok"]).toBe(false);
    expect(String(unleasedText["error"] ?? "")).toContain("ControllerLease");

    sendV2Bin(encodeDatagramPacket({ kind: "pointer", seq: 1, x: 60, y: 30, buttons: 1 }));
    sendV2Bin(encodeDatagramPacket({ kind: "pointer", seq: 2, x: 60, y: 30, buttons: 0 }));
    sendV2Bin(
      encodeDatagramPacket({
        kind: "scroll",
        seq: 1,
        scrollNodeId: 0n,
        x: 0,
        y: 120,
        velX: 0,
        velY: 0,
      }),
    );
    // Barrier: runSessionStep drains inboundPackets before inboundTextMessages on the 4ms tick.
    const preLeaseDrainP = waitTextReply(v2Ws, (m) => m["id"] === 970);
    v2Ws.send(JSON.stringify({ id: 970, type: "insertText", text: "nope-after-datagrams" }));
    expect((await preLeaseDrainP)["ok"]).toBe(false);
    const preLeaseCheck = (await cdpRestored.client.send(
      "Runtime.evaluate",
      {
        expression:
          "JSON.stringify({ active: document.activeElement?.id ?? null, y: window.scrollY })",
        returnByValue: true,
      },
      sid2,
    )) as { result?: { value?: string } };
    expect(JSON.parse(preLeaseCheck.result?.value ?? "{}")).toEqual({ active: "pwd", y: 0 });

    await cdpRestored.client.send("Parawing.approveControllerLease", { leaseId });

    // Mismatched leaseId on /rbi/ws releaseControllerLease is rejected cleanly.
    const wrongRelP = waitTextReply(v2Ws, (m) => m["id"] === 98);
    v2Ws.send(JSON.stringify({ id: 98, type: "releaseControllerLease", leaseId: "ctrl-wrong" }));
    expect((await wrongRelP)["ok"]).toBe(false);

    // Agent CDP mutations and agent observation stay paused during human takeover.
    cdpRestored.client.events.length = 0;
    const blockedEval = await cdpRestored.client.send(
      "Runtime.evaluate",
      { expression: "document.getElementById('draft').value = 'hijack'" },
      sid2,
    );
    expect(String(blockedEval.error ?? "")).toContain("active human controller lease");

    // Human viewer focuses #draft and types via /rbi/ws + viewer CDP while KSC2 streams continue.
    const takeoverSceneP = waitBinaryPacket(
      v2Ws,
      (pkt) => pkt.kind === RbiV2PacketKind.ReliableFrame,
    );
    sendV2Bin(encodeDatagramPacket({ kind: "pointer", seq: 3, x: 60, y: 30, buttons: 1 }));
    sendV2Bin(encodeDatagramPacket({ kind: "pointer", seq: 4, x: 60, y: 30, buttons: 0 }));
    const replyP = waitTextReply(v2Ws, (m) => m["id"] === 99);
    v2Ws.send(JSON.stringify({ id: 99, type: "insertText", text: "-ok" }));
    const reply = await replyP;
    expect(reply["ok"]).toBe(true);
    await takeoverSceneP;

    const viewerInsert = await cdpViewer.client.send("Input.insertText", { text: "!" }, sid2);
    expect(viewerInsert.error).toBeUndefined();

    expect(
      cdpRestored.client.events.some(
        (ev) =>
          ev.method === "Page.screencastFrame" ||
          ev.method === "Parawing.sceneFrame" ||
          ev.method === "Runtime.consoleAPICalled" ||
          ev.method === "Network.requestWillBeSent",
      ),
    ).toBe(false);

    // Handback via /rbi/ws control message restores agent control and console observation.
    const relReplyP = waitTextReply(v2Ws, (m) => m["id"] === 100);
    v2Ws.send(JSON.stringify({ id: 100, type: "releaseControllerLease", leaseId }));
    expect((await relReplyP)["ok"]).toBe(true);

    const postReleaseTextP = waitTextReply(v2Ws, (m) => m["id"] === 101);
    v2Ws.send(JSON.stringify({ id: 101, type: "insertText", text: "after" }));
    expect((await postReleaseTextP)["ok"]).toBe(false);

    const afterEval = (await cdpRestored.client.send(
      "Runtime.evaluate",
      {
        expression: "console.log('handback-live'); document.getElementById('draft').value",
        returnByValue: true,
      },
      sid2,
    )) as { result?: { value?: unknown }; error?: unknown };
    expect(afterEval.error).toBeUndefined();
    expect(afterEval.result?.value).toBe("AB-ok!");
    await cdpRestored.client.waitEvent((ev) => ev.method === "Runtime.consoleAPICalled");

    await cdpRestored.client.send("Parawing.destroySession", { reason: "test-done" });
  } finally {
    await closeSocketCleanly(v2Ws);
    await Promise.all([
      closeSocketCleanly(cdpViewer?.ws ?? null),
      closeSocketCleanly(cdpRestored?.ws ?? null),
      closeSocketCleanly(cdpWarm?.ws ?? null),
      closeSocketCleanly(cdp1?.ws ?? null),
    ]);
  }
});

test("pauses DOM, Page, Runtime, and Network events during ControllerLease takeover and emits DOM.documentUpdated on handback", async () => {
  const ksSessionId = `e2e-obs-pause-${crypto.randomUUID()}`;
  const ksUserId = "e2e-obs-user";
  const nextHtml = [
    '<div id="arrived">next</div>',
    "<script>",
    'console.log("nav-console-leak");',
    'fetch("/__fixtures/policy-doc.html?body=sub").catch(function(){});',
    "</script>",
  ].join("");
  const nextUrl = `https://ks.invalid/__fixtures/policy-doc.html?body=${encodeURIComponent(nextHtml)}`;
  const startHtml = [
    "<button id='mutBtn' style='position:absolute;top:10px;left:10px;width:180px;height:40px' ",
    "onclick=\"var s=document.getElementById('status');s.setAttribute('data-mut','viewer');",
    "var p=document.createElement('p');p.textContent='added';s.appendChild(p);",
    "console.log('viewer-dom-mutated');\">Mutate</button>",
    `<a id="navLink" href="${nextUrl}" style="position:absolute;top:70px;left:10px;width:180px;height:40px;display:block">Next</a>`,
    "<div id='status'>init</div>",
  ].join("");
  const startUrl = `https://ks.invalid/__fixtures/policy-doc.html?body=${encodeURIComponent(startHtml)}`;

  let cdpAgent: { ws: WorkerdWebSocket; client: CdpClient } | null = null;
  let cdpViewer: { ws: WorkerdWebSocket; client: CdpClient } | null = null;

  try {
    cdpAgent = await openCdpClient(
      `?ksSessionId=${encodeURIComponent(ksSessionId)}&ksUserId=${encodeURIComponent(ksUserId)}`,
    );
    await cdpAgent.client.waitEvent((ev) => ev.method === "Parawing.sessionAttached");
    const created = (await cdpAgent.client.send("Target.createTarget", {
      url: "about:blank",
    })) as { targetId?: string };
    const pageId = String(created.targetId ?? "");
    const att = (await cdpAgent.client.send("Target.attachToTarget", {
      targetId: pageId,
      flatten: true,
    })) as { sessionId?: string };
    const sid = String(att.sessionId ?? "");

    await cdpAgent.client.send("DOM.enable", {}, sid);
    await cdpAgent.client.send("Page.enable", {}, sid);
    await cdpAgent.client.send("Runtime.enable", {}, sid);
    await cdpAgent.client.send("Network.enable", {}, sid);
    await cdpAgent.client.send("Page.navigate", { url: startUrl }, sid);
    await cdpAgent.client.waitEvent((ev) => ev.method === "Page.loadEventFired");
    await cdpAgent.client.send("DOM.getDocument", {}, sid);

    cdpViewer = await openCdpClient(
      `?ksSessionId=${encodeURIComponent(ksSessionId)}&ksUserId=${encodeURIComponent(ksUserId)}&ksRole=viewer`,
    );
    await cdpViewer.client.waitEvent((ev) => ev.method === "Parawing.sessionAttached");
    const leaseReq = (await cdpViewer.client.send("Parawing.requestControllerLease", {
      targetId: pageId,
      requesterId: "human-viewer",
      pauseObservation: true,
    })) as { lease?: { leaseId?: string } };
    const leaseId = String(leaseReq.lease?.leaseId ?? "");
    expect(leaseId.startsWith("ctrl-")).toBe(true);
    await cdpAgent.client.send("Parawing.approveControllerLease", { leaseId });

    cdpAgent.client.events.length = 0;

    // Dispatch viewer DOM-mutating input while ControllerLease pauses agent observation.
    await cdpViewer.client.send(
      "Input.dispatchMouseEvent",
      { type: "mousePressed", x: 50, y: 25, button: "left", buttons: 1, clickCount: 1 },
      sid,
    );
    await cdpViewer.client.send(
      "Input.dispatchMouseEvent",
      { type: "mouseReleased", x: 50, y: 25, button: "left", buttons: 0, clickCount: 1 },
      sid,
    );
    await new Promise((resolve) => setTimeout(resolve, 250));

    // Dispatch viewer navigation by clicking the link while ControllerLease stays active.
    await cdpViewer.client.send(
      "Input.dispatchMouseEvent",
      { type: "mousePressed", x: 50, y: 85, button: "left", buttons: 1, clickCount: 1 },
      sid,
    );
    await cdpViewer.client.send(
      "Input.dispatchMouseEvent",
      { type: "mouseReleased", x: 50, y: 85, button: "left", buttons: 0, clickCount: 1 },
      sid,
    );

    let navDone = false;
    for (let attempt = 0; attempt < 40; attempt++) {
      const hist = (await cdpViewer.client.send("Page.getNavigationHistory", {}, sid)) as {
        currentIndex?: number;
        entries?: Array<{ url?: string }>;
      };
      const curUrl = hist.entries?.[hist.currentIndex ?? 0]?.url ?? "";
      if (curUrl.includes("nav-console-leak")) {
        navDone = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect(navDone).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 250));

    const leaked = cdpAgent.client.events.filter((ev) =>
      ["DOM.", "Page.", "Runtime.", "Network.", "CSS.", "Log.", "Fetch."].some((p) =>
        ev.method.startsWith(p),
      ),
    );
    expect(leaked).toEqual([]);

    // Release lease and verify DOM.documentUpdated + normal agent observation resume.
    cdpAgent.client.events.length = 0;
    const relRes = await cdpViewer.client.send("Parawing.releaseControllerLease", { leaseId });
    expect(relRes.error).toBeUndefined();
    await cdpAgent.client.waitEvent(
      (ev) => ev.method === "DOM.documentUpdated" && ev.sessionId === sid,
    );

    await cdpAgent.client.send("DOM.getDocument", {}, sid);
    await cdpAgent.client.send(
      "Runtime.evaluate",
      {
        expression:
          "document.getElementById('arrived').setAttribute('data-after','ok');" +
          "console.log('resumed-log');" +
          "fetch('/__fixtures/policy-doc.html?body=after').catch(function(){});",
      },
      sid,
    );
    await cdpAgent.client.waitEvent(
      (ev) => ev.method === "Runtime.consoleAPICalled",
      8_000,
      "Runtime.consoleAPICalled",
    );
    await cdpAgent.client.waitEvent(
      (ev) => ev.method === "Network.requestWillBeSent",
      8_000,
      "Network.requestWillBeSent",
    );
    await cdpAgent.client.waitEvent(
      (ev) => ev.method === "DOM.attributeModified",
      8_000,
      "DOM.attributeModified",
    );

    await cdpAgent.client.send("Page.navigate", { url: startUrl }, sid);
    await cdpAgent.client.waitEvent(
      (ev) => ev.method === "Page.frameNavigated",
      8_000,
      "Page.frameNavigated",
    );
    await cdpAgent.client.waitEvent(
      (ev) => ev.method === "Page.loadEventFired",
      8_000,
      "Page.loadEventFired",
    );

    await cdpAgent.client.send("Parawing.destroySession", { reason: "test-obs-done" });
  } finally {
    await Promise.all([
      closeSocketCleanly(cdpViewer?.ws ?? null),
      closeSocketCleanly(cdpAgent?.ws ?? null),
    ]);
  }
});
