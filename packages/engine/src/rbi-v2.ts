// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// S7 Viewer Channel: binary KSC2 reliable frames, latest-wins datagrams, credit flow control,
// and reattachWithTileHashes delta resync off base64-in-CDP.

export const KSV2_WIRE_MAGIC_0 = 0x4b; // 'K'
export const KSV2_WIRE_MAGIC_1 = 0x56; // 'V'
export const KSV2_WIRE_MAGIC_2 = 0x32; // '2'
export const KSV2_WIRE_MAGIC_3 = 0x01; // version 1

const HEADER_BYTES = 5;
const MAX_TILE_HASHES = 262_144;
const MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
const INTEREST_REF_VELOCITY_PX_PER_SEC = 2000.0;
const DEFAULT_INITIAL_CREDITS = 2;
const DEFAULT_MAX_CREDITS = 16;

export enum RbiV2PacketKind {
  ReliableFrame = 1,
  CreditGrant = 2,
  ReattachWithTileHashes = 3,
  DatagramScroll = 4,
  DatagramPointer = 5,
  DatagramAnimTick = 6,
  DeltaResyncAck = 7,
}

export interface RectV2Ts {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface ViewportStateV2 {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface ScrollDatagramV2 {
  kind: "scroll";
  seq: number;
  scrollNodeId: bigint;
  x: number;
  y: number;
  velX: number;
  velY: number;
}

export interface PointerDatagramV2 {
  kind: "pointer";
  seq: number;
  x: number;
  y: number;
  buttons: number;
}

export interface AnimTickDatagramV2 {
  kind: "animTick";
  seq: number;
  tMs: number;
}

export type ViewerDatagramV2 = ScrollDatagramV2 | PointerDatagramV2 | AnimTickDatagramV2;

export type DecodedRbiV2Packet =
  | {
      kind: RbiV2PacketKind.ReliableFrame;
      frameSeq: number;
      baseSeq: number;
      tileCount: number;
      payload: Uint8Array;
    }
  | {
      kind: RbiV2PacketKind.CreditGrant;
      creditsGranted: number;
      ackedFrameSeq: number;
    }
  | {
      kind: RbiV2PacketKind.ReattachWithTileHashes;
      lastFrameSeq: number;
      viewport: ViewportStateV2;
      velX: number;
      velY: number;
      knownTileHashes: bigint[];
    }
  | { kind: RbiV2PacketKind.DatagramScroll; datagram: ScrollDatagramV2 }
  | { kind: RbiV2PacketKind.DatagramPointer; datagram: PointerDatagramV2 }
  | { kind: RbiV2PacketKind.DatagramAnimTick; datagram: AnimTickDatagramV2 }
  | {
      kind: RbiV2PacketKind.DeltaResyncAck;
      resumedFromSeq: number;
      prunedKnownTiles: number;
      payload: Uint8Array;
    };

export interface RbiV2Transport {
  sendReliable(packet: Uint8Array): void;
  sendDatagram?(packet: Uint8Array): void;
}

export interface IndexedTileV2 {
  contentHash: bigint;
  bounds: RectV2Ts;
  encodedBytes: Uint8Array;
}

export interface ReliableFrameEntry {
  frameSeq: number;
  baseSeq: number;
  tileCount: number;
  payload: Uint8Array;
}

export interface ReattachResyncResult {
  resumedFromSeq: number;
  prunedKnownTiles: number;
  payload: Uint8Array;
}

export type ReattachResyncHandler = (msg: {
  lastFrameSeq: number;
  viewport: ViewportStateV2;
  velX: number;
  velY: number;
  knownTileHashes: Set<bigint>;
  interestRect: RectV2Ts;
}) => ReattachResyncResult | null;

export interface RbiV2ServerStats {
  availableCredits: number;
  maxCredits: number;
  sentReliableFrames: number;
  queuedReliableFrames: number;
  sentDatagrams: number;
  coalescedDatagrams: number;
  reattachCount: number;
  prunedKnownTilesTotal: number;
}

function writeHeader(view: DataView, kind: RbiV2PacketKind): void {
  view.setUint8(0, KSV2_WIRE_MAGIC_0);
  view.setUint8(1, KSV2_WIRE_MAGIC_1);
  view.setUint8(2, KSV2_WIRE_MAGIC_2);
  view.setUint8(3, KSV2_WIRE_MAGIC_3);
  view.setUint8(4, kind);
}

function assertHeader(bytes: Uint8Array, minBytes: number): { view: DataView; kind: number } {
  if (bytes.byteLength < minBytes) {
    throw new Error(`KSV2 packet truncated: got ${bytes.byteLength}, need >= ${minBytes}`);
  }
  if (
    bytes[0] !== KSV2_WIRE_MAGIC_0 ||
    bytes[1] !== KSV2_WIRE_MAGIC_1 ||
    bytes[2] !== KSV2_WIRE_MAGIC_2 ||
    bytes[3] !== KSV2_WIRE_MAGIC_3
  ) {
    throw new Error("Invalid KSV2 packet magic");
  }
  return {
    view: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    kind: bytes[4]!,
  };
}

export function encodeReliableFramePacket(entry: ReliableFrameEntry): Uint8Array {
  const out = new Uint8Array(HEADER_BYTES + 16 + entry.payload.byteLength);
  const view = new DataView(out.buffer);
  writeHeader(view, RbiV2PacketKind.ReliableFrame);
  view.setUint32(5, entry.frameSeq >>> 0, true);
  view.setUint32(9, entry.baseSeq >>> 0, true);
  view.setUint32(13, entry.tileCount >>> 0, true);
  view.setUint32(17, entry.payload.byteLength >>> 0, true);
  out.set(entry.payload, 21);
  return out;
}

export function encodeCreditGrantPacket(creditsGranted: number, ackedFrameSeq: number): Uint8Array {
  const out = new Uint8Array(HEADER_BYTES + 8);
  const view = new DataView(out.buffer);
  writeHeader(view, RbiV2PacketKind.CreditGrant);
  view.setUint32(5, Math.max(0, creditsGranted) >>> 0, true);
  view.setUint32(9, Math.max(0, ackedFrameSeq) >>> 0, true);
  return out;
}

export function encodeReattachWithTileHashesPacket(
  lastFrameSeq: number,
  knownTileHashes: Iterable<bigint>,
  viewport: ViewportStateV2,
  velX: number,
  velY: number,
): Uint8Array {
  const hashes = Array.from(knownTileHashes);
  if (hashes.length > MAX_TILE_HASHES) {
    throw new Error(`Too many known tile hashes: ${hashes.length}`);
  }
  const fixedBytes = HEADER_BYTES + 32;
  const out = new Uint8Array(fixedBytes + hashes.length * 8);
  const view = new DataView(out.buffer);
  writeHeader(view, RbiV2PacketKind.ReattachWithTileHashes);
  view.setUint32(5, lastFrameSeq >>> 0, true);
  view.setFloat32(9, viewport.x, true);
  view.setFloat32(13, viewport.y, true);
  view.setFloat32(17, viewport.w, true);
  view.setFloat32(21, viewport.h, true);
  view.setFloat32(25, velX, true);
  view.setFloat32(29, velY, true);
  view.setUint32(33, hashes.length >>> 0, true);
  let off = 37;
  for (const h of hashes) {
    view.setBigUint64(off, BigInt.asUintN(64, h), true);
    off += 8;
  }
  return out;
}

export function encodeDatagramPacket(datagram: ViewerDatagramV2): Uint8Array {
  if (datagram.kind === "scroll") {
    const out = new Uint8Array(HEADER_BYTES + 28);
    const view = new DataView(out.buffer);
    writeHeader(view, RbiV2PacketKind.DatagramScroll);
    view.setUint32(5, datagram.seq >>> 0, true);
    view.setBigUint64(9, BigInt.asUintN(64, datagram.scrollNodeId), true);
    view.setFloat32(17, datagram.x, true);
    view.setFloat32(21, datagram.y, true);
    view.setFloat32(25, datagram.velX, true);
    view.setFloat32(29, datagram.velY, true);
    return out;
  }
  if (datagram.kind === "pointer") {
    const out = new Uint8Array(HEADER_BYTES + 13);
    const view = new DataView(out.buffer);
    writeHeader(view, RbiV2PacketKind.DatagramPointer);
    view.setUint32(5, datagram.seq >>> 0, true);
    view.setFloat32(9, datagram.x, true);
    view.setFloat32(13, datagram.y, true);
    view.setUint8(17, datagram.buttons & 0xff);
    return out;
  }
  const out = new Uint8Array(HEADER_BYTES + 12);
  const view = new DataView(out.buffer);
  writeHeader(view, RbiV2PacketKind.DatagramAnimTick);
  view.setUint32(5, datagram.seq >>> 0, true);
  view.setFloat64(9, datagram.tMs, true);
  return out;
}

export function encodeDeltaResyncAckPacket(result: ReattachResyncResult): Uint8Array {
  const out = new Uint8Array(HEADER_BYTES + 12 + result.payload.byteLength);
  const view = new DataView(out.buffer);
  writeHeader(view, RbiV2PacketKind.DeltaResyncAck);
  view.setUint32(5, result.resumedFromSeq >>> 0, true);
  view.setUint32(9, result.prunedKnownTiles >>> 0, true);
  view.setUint32(13, result.payload.byteLength >>> 0, true);
  out.set(result.payload, 17);
  return out;
}

function decodePayloadFrame(
  bytes: Uint8Array,
  view: DataView,
  kind: RbiV2PacketKind.ReliableFrame | RbiV2PacketKind.DeltaResyncAck,
): DecodedRbiV2Packet {
  if (kind === RbiV2PacketKind.ReliableFrame) {
    if (bytes.byteLength < 21) throw new Error("ReliableFrame header truncated");
    const frameSeq = view.getUint32(5, true);
    const baseSeq = view.getUint32(9, true);
    const tileCount = view.getUint32(13, true);
    const len = view.getUint32(17, true);
    if (len > MAX_PAYLOAD_BYTES || 21 + len > bytes.byteLength) {
      throw new Error(`ReliableFrame payload invalid length ${len}`);
    }
    return { kind, frameSeq, baseSeq, tileCount, payload: bytes.slice(21, 21 + len) };
  }
  if (bytes.byteLength < 17) throw new Error("DeltaResyncAck header truncated");
  const resumedFromSeq = view.getUint32(5, true);
  const prunedKnownTiles = view.getUint32(9, true);
  const len = view.getUint32(13, true);
  if (len > MAX_PAYLOAD_BYTES || 17 + len > bytes.byteLength) {
    throw new Error(`DeltaResyncAck payload invalid length ${len}`);
  }
  return { kind, resumedFromSeq, prunedKnownTiles, payload: bytes.slice(17, 17 + len) };
}

function decodeReattachPacket(bytes: Uint8Array, view: DataView): DecodedRbiV2Packet {
  if (bytes.byteLength < 37) throw new Error("ReattachWithTileHashes header truncated");
  const lastFrameSeq = view.getUint32(5, true);
  const viewport: ViewportStateV2 = {
    x: view.getFloat32(9, true),
    y: view.getFloat32(13, true),
    w: view.getFloat32(17, true),
    h: view.getFloat32(21, true),
  };
  const velX = view.getFloat32(25, true);
  const velY = view.getFloat32(29, true);
  const count = view.getUint32(33, true);
  if (count > MAX_TILE_HASHES || 37 + count * 8 > bytes.byteLength) {
    throw new Error(`ReattachWithTileHashes invalid hash count ${count}`);
  }
  const knownTileHashes: bigint[] = [];
  let off = 37;
  for (let i = 0; i < count; i++) {
    knownTileHashes.push(view.getBigUint64(off, true));
    off += 8;
  }
  return {
    kind: RbiV2PacketKind.ReattachWithTileHashes,
    lastFrameSeq,
    viewport,
    velX,
    velY,
    knownTileHashes,
  };
}

export function decodeRbiV2Packet(bytes: Uint8Array): DecodedRbiV2Packet {
  const { view, kind } = assertHeader(bytes, HEADER_BYTES);
  switch (kind) {
    case RbiV2PacketKind.ReliableFrame:
    case RbiV2PacketKind.DeltaResyncAck:
      return decodePayloadFrame(bytes, view, kind);
    case RbiV2PacketKind.CreditGrant: {
      if (bytes.byteLength < 13) throw new Error("CreditGrant truncated");
      return {
        kind: RbiV2PacketKind.CreditGrant,
        creditsGranted: view.getUint32(5, true),
        ackedFrameSeq: view.getUint32(9, true),
      };
    }
    case RbiV2PacketKind.ReattachWithTileHashes:
      return decodeReattachPacket(bytes, view);
    case RbiV2PacketKind.DatagramScroll: {
      if (bytes.byteLength < 33) throw new Error("DatagramScroll truncated");
      return {
        kind: RbiV2PacketKind.DatagramScroll,
        datagram: {
          kind: "scroll",
          seq: view.getUint32(5, true),
          scrollNodeId: view.getBigUint64(9, true),
          x: view.getFloat32(17, true),
          y: view.getFloat32(21, true),
          velX: view.getFloat32(25, true),
          velY: view.getFloat32(29, true),
        },
      };
    }
    case RbiV2PacketKind.DatagramPointer: {
      if (bytes.byteLength < 18) throw new Error("DatagramPointer truncated");
      return {
        kind: RbiV2PacketKind.DatagramPointer,
        datagram: {
          kind: "pointer",
          seq: view.getUint32(5, true),
          x: view.getFloat32(9, true),
          y: view.getFloat32(13, true),
          buttons: view.getUint8(17),
        },
      };
    }
    case RbiV2PacketKind.DatagramAnimTick: {
      if (bytes.byteLength < 17) throw new Error("DatagramAnimTick truncated");
      return {
        kind: RbiV2PacketKind.DatagramAnimTick,
        datagram: {
          kind: "animTick",
          seq: view.getUint32(5, true),
          tMs: view.getFloat64(9, true),
        },
      };
    }
    default:
      throw new Error(`Unknown KSV2 packet kind: ${kind}`);
  }
}

function axisInterestSpan(pos: number, dim: number, velocity: number): [number, number] {
  const size = Number.isFinite(dim) ? Math.max(0, dim) : 0;
  const v = Number.isFinite(velocity) ? velocity : 0;
  const scale = Math.min(Math.abs(v) / INTEREST_REF_VELOCITY_PX_PER_SEC, 1.0);
  const ahead = 2.0 * size * scale;
  const behind = size;
  if (v >= 0) {
    return [Math.max(0, pos - behind), pos + size + ahead];
  }
  return [Math.max(0, pos - ahead), pos + size + behind];
}

export function computeInterestRectV2(
  viewport: ViewportStateV2,
  velX: number,
  velY: number,
): RectV2Ts {
  const [x0, x1] = axisInterestSpan(viewport.x, viewport.w, velX);
  const [y0, y1] = axisInterestSpan(viewport.y, viewport.h, velY);
  return { x: x0, y: y0, w: Math.max(0, x1 - x0), h: Math.max(0, y1 - y0) };
}

function rectsIntersect(a: RectV2Ts, b: RectV2Ts): boolean {
  return a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;
}

export function selectDeltaTilesForClient(
  candidateTiles: readonly IndexedTileV2[],
  interestRect: RectV2Ts,
  knownHashes: ReadonlySet<bigint>,
): { deltaTiles: IndexedTileV2[]; prunedKnown: number; culledOutside: number } {
  const deltaTiles: IndexedTileV2[] = [];
  const emittedHashes = new Set<bigint>();
  let prunedKnown = 0;
  let culledOutside = 0;
  for (const tile of candidateTiles) {
    if (!rectsIntersect(tile.bounds, interestRect)) {
      culledOutside++;
      continue;
    }
    if (knownHashes.has(tile.contentHash) || emittedHashes.has(tile.contentHash)) {
      prunedKnown++;
      continue;
    }
    emittedHashes.add(tile.contentHash);
    deltaTiles.push(tile);
  }
  return { deltaTiles, prunedKnown, culledOutside };
}

export function createWebSocketBinaryTransport(ws: {
  send(data: ArrayBufferLike | ArrayBufferView): void;
  readyState: number;
}): RbiV2Transport {
  const sendBinary = (packet: Uint8Array): void => {
    if (ws.readyState !== 1) return;
    ws.send(packet);
  };
  return { sendReliable: sendBinary, sendDatagram: sendBinary };
}

export class RbiV2ServerChannel {
  private readonly transport: RbiV2Transport;
  private readonly maxCredits: number;
  private availableCredits: number;
  private readonly reliableQueue: ReliableFrameEntry[] = [];
  private readonly pendingScrollDatagrams: Map<bigint, ScrollDatagramV2> = new Map();
  private pendingPointerDatagram: PointerDatagramV2 | null = null;
  private pendingAnimDatagram: AnimTickDatagramV2 | null = null;
  private readonly latestInboundScrollSeq: Map<bigint, number> = new Map();
  private latestInboundPointerSeq = 0;
  private knownClientHashes: Set<bigint> = new Set();
  private sentReliableFrames = 0;
  private sentDatagrams = 0;
  private coalescedDatagrams = 0;
  private reattachCount = 0;
  private prunedKnownTilesTotal = 0;
  private latestInboundScroll: Map<bigint, ScrollDatagramV2> = new Map();
  private latestInboundPointer: PointerDatagramV2 | null = null;
  private readonly onReattachResync?: ReattachResyncHandler;

  constructor(
    transport: RbiV2Transport,
    opts?: {
      initialCredits?: number;
      maxCredits?: number;
      onReattachResync?: ReattachResyncHandler;
    },
  ) {
    this.transport = transport;
    this.maxCredits = Math.max(1, opts?.maxCredits ?? DEFAULT_MAX_CREDITS);
    this.availableCredits = Math.min(
      this.maxCredits,
      Math.max(0, opts?.initialCredits ?? DEFAULT_INITIAL_CREDITS),
    );
    this.onReattachResync = opts?.onReattachResync;
  }

  enqueueReliableFrame(entry: ReliableFrameEntry): boolean {
    if (this.availableCredits > 0 && this.reliableQueue.length === 0) {
      this.availableCredits--;
      this.sentReliableFrames++;
      this.transport.sendReliable(encodeReliableFramePacket(entry));
      return true;
    }
    this.reliableQueue.push(entry);
    return false;
  }

  drainReliable(): number {
    let drained = 0;
    while (this.availableCredits > 0 && this.reliableQueue.length > 0) {
      const next = this.reliableQueue.shift()!;
      this.availableCredits--;
      this.sentReliableFrames++;
      this.transport.sendReliable(encodeReliableFramePacket(next));
      drained++;
    }
    return drained;
  }

  enqueueDatagram(datagram: ViewerDatagramV2): void {
    if (datagram.kind === "scroll") {
      const prev = this.pendingScrollDatagrams.get(datagram.scrollNodeId);
      if (prev) {
        if (datagram.seq <= prev.seq) return;
        this.coalescedDatagrams++;
      }
      this.pendingScrollDatagrams.set(datagram.scrollNodeId, datagram);
      return;
    }
    if (datagram.kind === "pointer") {
      if (this.pendingPointerDatagram) {
        if (datagram.seq <= this.pendingPointerDatagram.seq) return;
        this.coalescedDatagrams++;
      }
      this.pendingPointerDatagram = datagram;
      return;
    }
    if (this.pendingAnimDatagram) {
      if (datagram.seq <= this.pendingAnimDatagram.seq) return;
      this.coalescedDatagrams++;
    }
    this.pendingAnimDatagram = datagram;
  }

  flushDatagrams(): number {
    const sendFn = this.transport.sendDatagram ?? this.transport.sendReliable;
    let sent = 0;
    for (const scroll of this.pendingScrollDatagrams.values()) {
      sendFn(encodeDatagramPacket(scroll));
      sent++;
    }
    this.pendingScrollDatagrams.clear();
    if (this.pendingPointerDatagram) {
      sendFn(encodeDatagramPacket(this.pendingPointerDatagram));
      this.pendingPointerDatagram = null;
      sent++;
    }
    if (this.pendingAnimDatagram) {
      sendFn(encodeDatagramPacket(this.pendingAnimDatagram));
      this.pendingAnimDatagram = null;
      sent++;
    }
    this.sentDatagrams += sent;
    return sent;
  }

  handleClientPacket(bytes: Uint8Array): DecodedRbiV2Packet {
    const msg = decodeRbiV2Packet(bytes);
    if (msg.kind === RbiV2PacketKind.CreditGrant) {
      this.availableCredits = Math.min(this.maxCredits, this.availableCredits + msg.creditsGranted);
      this.drainReliable();
      return msg;
    }
    if (msg.kind === RbiV2PacketKind.ReattachWithTileHashes) {
      this.reattachCount++;
      this.knownClientHashes = new Set(msg.knownTileHashes);
      const interestRect = computeInterestRectV2(msg.viewport, msg.velX, msg.velY);
      const resync = this.onReattachResync?.({
        lastFrameSeq: msg.lastFrameSeq,
        viewport: msg.viewport,
        velX: msg.velX,
        velY: msg.velY,
        knownTileHashes: this.knownClientHashes,
        interestRect,
      });
      if (resync) {
        this.prunedKnownTilesTotal += resync.prunedKnownTiles;
        this.transport.sendReliable(encodeDeltaResyncAckPacket(resync));
      }
      return msg;
    }
    if (msg.kind === RbiV2PacketKind.DatagramScroll) {
      const d = msg.datagram;
      const last = this.latestInboundScrollSeq.get(d.scrollNodeId) ?? -1;
      if (d.seq > last) {
        this.latestInboundScrollSeq.set(d.scrollNodeId, d.seq);
        this.latestInboundScroll.set(d.scrollNodeId, d);
      }
      return msg;
    }
    if (msg.kind === RbiV2PacketKind.DatagramPointer) {
      const d = msg.datagram;
      if (d.seq > this.latestInboundPointerSeq) {
        this.latestInboundPointerSeq = d.seq;
        this.latestInboundPointer = d;
      }
      return msg;
    }
    return msg;
  }

  takeLatestInboundScroll(scrollNodeId: bigint): ScrollDatagramV2 | null {
    const val = this.latestInboundScroll.get(scrollNodeId) ?? null;
    if (val) this.latestInboundScroll.delete(scrollNodeId);
    return val;
  }

  takeLatestInboundPointer(): PointerDatagramV2 | null {
    const val = this.latestInboundPointer;
    this.latestInboundPointer = null;
    return val;
  }

  knownHashes(): ReadonlySet<bigint> {
    return this.knownClientHashes;
  }

  stats(): RbiV2ServerStats {
    return {
      availableCredits: this.availableCredits,
      maxCredits: this.maxCredits,
      sentReliableFrames: this.sentReliableFrames,
      queuedReliableFrames: this.reliableQueue.length,
      sentDatagrams: this.sentDatagrams,
      coalescedDatagrams: this.coalescedDatagrams,
      reattachCount: this.reattachCount,
      prunedKnownTilesTotal: this.prunedKnownTilesTotal,
    };
  }
}

export class RbiV2ClientChannel {
  private readonly transport: RbiV2Transport;
  private readonly knownHashes: Set<bigint> = new Set();
  private lastFrameSeq = 0;

  constructor(transport: RbiV2Transport) {
    this.transport = transport;
  }

  registerKnownTiles(hashes: Iterable<bigint>): void {
    for (const h of hashes) this.knownHashes.add(h);
  }

  evictKnownTiles(hashes: Iterable<bigint>): void {
    for (const h of hashes) this.knownHashes.delete(h);
  }

  acknowledgeFrame(frameSeq: number, creditGrant = 1): void {
    if (frameSeq > this.lastFrameSeq) this.lastFrameSeq = frameSeq;
    this.transport.sendReliable(encodeCreditGrantPacket(creditGrant, frameSeq));
  }

  sendLatestDatagram(datagram: ViewerDatagramV2): void {
    const sendFn = this.transport.sendDatagram ?? this.transport.sendReliable;
    sendFn(encodeDatagramPacket(datagram));
  }

  reattachWithTileHashes(viewport: ViewportStateV2, velX: number, velY: number): Uint8Array {
    const packet = encodeReattachWithTileHashesPacket(
      this.lastFrameSeq,
      this.knownHashes,
      viewport,
      velX,
      velY,
    );
    this.transport.sendReliable(packet);
    return packet;
  }

  knownTileSet(): ReadonlySet<bigint> {
    return this.knownHashes;
  }
}

const KSC2_MAGIC_0 = 0x4b; // 'K'
const KSC2_MAGIC_1 = 0x53; // 'S'
const KSC2_MAGIC_2 = 0x43; // 'C'
const KSC2_MAGIC_3 = 0x32; // '2'
const KSC2_VERSION_1 = 1;
const KSC2_MAX_ITEMS = 65_536;
const KSC2_MAX_BLOB_BYTES = 16 * 1024 * 1024;

export interface Ksc2TileMetadata {
  tileCount: number;
  tileHashes: bigint[];
  invalidatedHashes: bigint[];
}

class Ksc2Reader {
  readonly view: DataView;
  readonly bytes: Uint8Array;
  pos = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  skip(n: number): boolean {
    if (n < 0 || this.pos + n > this.bytes.byteLength) return false;
    this.pos += n;
    return true;
  }

  u8(): number | null {
    if (this.pos + 1 > this.bytes.byteLength) return null;
    return this.bytes[this.pos++]!;
  }

  u32(): number | null {
    if (this.pos + 4 > this.bytes.byteLength) return null;
    const val = this.view.getUint32(this.pos, true);
    this.pos += 4;
    return val;
  }

  u64(): bigint | null {
    if (this.pos + 8 > this.bytes.byteLength) return null;
    const val = this.view.getBigUint64(this.pos, true);
    this.pos += 8;
    return val;
  }

  count(): number | null {
    const c = this.u32();
    if (c === null || c > KSC2_MAX_ITEMS) return null;
    return c;
  }

  skipBlob(): boolean {
    const len = this.u32();
    if (len === null || len > KSC2_MAX_BLOB_BYTES) return false;
    return this.skip(len);
  }
}

function skipScrollNodes(r: Ksc2Reader): boolean {
  const count = r.count();
  if (count === null) return false;
  for (let i = 0; i < count; i++) {
    if (!r.skip(48)) return false;
    const sx = r.count();
    if (sx === null || !r.skip(sx * 4)) return false;
    const sy = r.count();
    if (sy === null || !r.skip(sy * 4)) return false;
    if (!r.skip(4)) return false;
  }
  return true;
}

function skipLayerKind(r: Ksc2Reader): boolean {
  const tag = r.u8();
  if (tag === 0) return true;
  if (tag === 1) return r.skip(16);
  if (tag !== 2 || !r.skip(32)) return false;
  for (let i = 0; i < 4; i++) {
    const present = r.u8();
    if (present === null) return false;
    if (present !== 0 && !r.skip(4)) return false;
  }
  return true;
}

function skipAnimationCurve(r: Ksc2Reader): boolean {
  if (!r.skip(22)) return false;
  const kfCount = r.count();
  if (kfCount === null) return false;
  for (let k = 0; k < kfCount; k++) {
    if (!r.skip(4)) return false;
    const vtag = r.u8();
    if (vtag === 0) {
      if (!r.skip(4)) return false;
    } else if (vtag === 1) {
      if (!r.skip(24)) return false;
    } else {
      return false;
    }
    const etag = r.u8();
    if (etag === 2 && !r.skip(16)) return false;
    if (etag !== 0 && etag !== 1 && etag !== 2) return false;
  }
  return true;
}

function readLayerInvalidatedHashes(r: Ksc2Reader): bigint[] | null {
  const count = r.count();
  if (count === null) return null;
  const invalidated: bigint[] = [];
  for (let i = 0; i < count; i++) {
    if (!r.skip(16) || !skipLayerKind(r) || !r.skip(48)) return null;
    const animCount = r.count();
    if (animCount === null) return null;
    for (let a = 0; a < animCount; a++) {
      if (!skipAnimationCurve(r)) return null;
    }
    if (!r.skip(4)) return null;
    const refCount = r.count();
    if (refCount === null || !r.skip(refCount * 32)) return null;
    const invCount = r.count();
    if (invCount === null) return null;
    for (let j = 0; j < invCount; j++) {
      const h = r.u64();
      if (h === null) return null;
      invalidated.push(h);
    }
  }
  return invalidated;
}

function skipTextRun(r: Ksc2Reader): boolean {
  if (!r.skip(8) || !r.skipBlob() || !r.skip(29)) return false;
  const clusterCount = r.count();
  return clusterCount !== null && r.skip(clusterCount * 32);
}

function skipHitRect(r: Ksc2Reader): boolean {
  if (!r.skip(33)) return false;
  const hasUrl = r.u8();
  if (hasUrl === null) return false;
  if (hasUrl !== 0 && !r.skipBlob()) return false;
  return r.skip(2);
}

function readTilePayloadHashes(r: Ksc2Reader): { tileCount: number; tileHashes: bigint[] } | null {
  const tileCount = r.count();
  if (tileCount === null) return null;
  const tileHashes: bigint[] = [];
  for (let i = 0; i < tileCount; i++) {
    const hash = r.u64();
    if (hash === null || !r.skip(8) || !r.skipBlob()) return null;
    tileHashes.push(hash);
    const runCount = r.count();
    if (runCount === null) return null;
    for (let j = 0; j < runCount; j++) {
      if (!skipTextRun(r)) return null;
    }
    const hitCount = r.count();
    if (hitCount === null) return null;
    for (let j = 0; j < hitCount; j++) {
      if (!skipHitRect(r)) return null;
    }
  }
  return { tileCount, tileHashes };
}

export function extractKsc2TileMetadata(frameBytes: Uint8Array): Ksc2TileMetadata {
  const empty: Ksc2TileMetadata = { tileCount: 0, tileHashes: [], invalidatedHashes: [] };
  if (
    frameBytes.byteLength < 24 ||
    frameBytes[0] !== KSC2_MAGIC_0 ||
    frameBytes[1] !== KSC2_MAGIC_1 ||
    frameBytes[2] !== KSC2_MAGIC_2 ||
    frameBytes[3] !== KSC2_MAGIC_3
  ) {
    return empty;
  }
  const r = new Ksc2Reader(frameBytes);
  r.pos = 4;
  if (r.u32() !== KSC2_VERSION_1 || !r.skip(16)) return empty;
  if (!skipScrollNodes(r)) return empty;
  const invalidatedHashes = readLayerInvalidatedHashes(r);
  if (invalidatedHashes === null) return empty;
  const tileInfo = readTilePayloadHashes(r);
  if (tileInfo === null) return empty;
  return {
    tileCount: tileInfo.tileCount,
    tileHashes: tileInfo.tileHashes,
    invalidatedHashes,
  };
}
