// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import type { HandlerRegionInfo } from "@parawing/jsrpc-types/page-script";
import {
  RbiV2ClientChannel,
  RbiV2PacketKind,
  RbiV2ServerChannel,
  computeInterestRectV2,
  createWebSocketBinaryTransport,
  decodeRbiV2Packet,
  encodeDatagramPacket,
  encodeDeltaResyncAckPacket,
  encodeReattachWithTileHashesPacket,
  encodeReliableFramePacket,
  extractKsc2TileMetadata,
  selectDeltaTilesForClient,
  type IndexedTileV2,
  type RbiV2Transport,
} from "../src/rbi-v2.ts";
import {
  ClientInputJournal,
  canonicalFieldKey,
  classifyFieldSensitivity,
  type StableFieldKey,
} from "../src/rbi-input-journal.ts";

interface TrackerLike {
  recordMutation(targetNodeId: number, type: string, passive: boolean, added: boolean): void;
  reset(): void;
  activeMasks(): Map<number, number>;
  snapshotRegions(source: {
    documentNodeId: number;
    documentElementNodeId?: number;
    viewportWidth: number;
    viewportHeight: number;
    getBoundingRect(nodeId: number): { x: number; y: number; width: number; height: number } | null;
    getScrollInfo(nodeId: number): {
      clientWidth?: number;
      clientHeight?: number;
      scrollWidth?: number;
      scrollHeight?: number;
    } | null;
    parentNodeId(nodeId: number): number;
  }): HandlerRegionInfo[];
}

const handlerRegionsMod = (await vi.importActual("../../page-script/src/handler-regions.ts")) as {
  HANDLER_WHEEL: number;
  HANDLER_TOUCH_START: number;
  HANDLER_TOUCH_MOVE: number;
  HandlerRegionTracker: new () => TrackerLike;
};

afterEach(() => {
  vi.restoreAllMocks();
});

function makeIndexedTile(id: number, x: number, y: number, w = 256, h = 256): IndexedTileV2 {
  const encodedBytes = new Uint8Array(512);
  encodedBytes.fill((id * 37) & 0xff);
  return {
    contentHash: 0x1000_0000_0000_0000n + BigInt(id),
    bounds: { x, y, w, h },
    encodedBytes,
  };
}

describe("S7 RbiV2 viewer channel", () => {
  it("encodes binary frames off base64 and wraps binary WebSocket sends", () => {
    const sent: unknown[] = [];
    const ws = {
      readyState: 1,
      send: (data: ArrayBufferLike | ArrayBufferView): void => {
        sent.push(data);
      },
    };
    const transport = createWebSocketBinaryTransport(ws);
    const framePayload = new Uint8Array([0x4b, 0x53, 0x43, 0x32, 1, 2, 3, 4]);
    const server = new RbiV2ServerChannel(transport, { initialCredits: 2 });

    expect(
      server.enqueueReliableFrame({
        frameSeq: 7,
        baseSeq: 6,
        tileCount: 3,
        payload: framePayload,
      }),
    ).toBe(true);
    expect(sent.length).toBe(1);
    expect(sent[0]).toBeInstanceOf(Uint8Array);
    expect(typeof sent[0]).not.toBe("string");

    const decoded = decodeRbiV2Packet(sent[0] as Uint8Array);
    expect(decoded.kind).toBe(RbiV2PacketKind.ReliableFrame);
    if (decoded.kind === RbiV2PacketKind.ReliableFrame) {
      expect(decoded.frameSeq).toBe(7);
      expect(decoded.baseSeq).toBe(6);
      expect(decoded.tileCount).toBe(3);
      expect(decoded.payload).toEqual(framePayload);
    }

    expect(() => decodeRbiV2Packet(new Uint8Array([0, 0, 0, 0, 1]))).toThrow();
    expect(() =>
      decodeRbiV2Packet(
        encodeReliableFramePacket({
          frameSeq: 1,
          baseSeq: 0,
          tileCount: 0,
          payload: framePayload,
        }).slice(0, 8),
      ),
    ).toThrow();
  });

  it("enforces credit backpressure while coalescing latest-wins datagrams", () => {
    const reliableSent: Uint8Array[] = [];
    const datagramSent: Uint8Array[] = [];
    const transport: RbiV2Transport = {
      sendReliable: (pkt) => reliableSent.push(pkt),
      sendDatagram: (pkt) => datagramSent.push(pkt),
    };
    const server = new RbiV2ServerChannel(transport, { initialCredits: 2, maxCredits: 8 });
    const client = new RbiV2ClientChannel({
      sendReliable: (pkt) => server.handleClientPacket(pkt),
      sendDatagram: (pkt) => server.handleClientPacket(pkt),
    });

    for (let seq = 1; seq <= 4; seq++) {
      server.enqueueReliableFrame({
        frameSeq: seq,
        baseSeq: seq - 1,
        tileCount: 1,
        payload: new Uint8Array([seq]),
      });
    }
    expect(reliableSent.length).toBe(2);
    expect(server.stats().queuedReliableFrames).toBe(2);

    // Exhausted tree credits must never block latest-wins scroll/pointer datagrams.
    for (let seq = 1; seq <= 35; seq++) {
      server.enqueueDatagram({
        kind: "scroll",
        seq,
        scrollNodeId: 1n,
        x: 0,
        y: seq * 12,
        velX: 0,
        velY: 1800,
      });
    }
    // Stale lower seq is ignored cleanly.
    server.enqueueDatagram({
      kind: "scroll",
      seq: 10,
      scrollNodeId: 1n,
      x: 0,
      y: 0,
      velX: 0,
      velY: 0,
    });
    for (let seq = 1; seq <= 15; seq++) {
      server.enqueueDatagram({ kind: "pointer", seq, x: seq * 2, y: 120, buttons: 1 });
    }
    server.enqueueDatagram({ kind: "animTick", seq: 1, tMs: 16 });
    server.enqueueDatagram({ kind: "animTick", seq: 2, tMs: 32.5 });

    const flushed = server.flushDatagrams();
    expect(flushed).toBe(3);
    expect(datagramSent.length).toBe(3);
    expect(server.stats().coalescedDatagrams).toBe(34 + 14 + 1);

    const decodedScroll = decodeRbiV2Packet(datagramSent[0]!);
    expect(decodedScroll.kind).toBe(RbiV2PacketKind.DatagramScroll);
    if (decodedScroll.kind === RbiV2PacketKind.DatagramScroll) {
      expect(decodedScroll.datagram.seq).toBe(35);
      expect(decodedScroll.datagram.y).toBe(35 * 12);
    }

    const decodedPointer = decodeRbiV2Packet(datagramSent[1]!);
    expect(decodedPointer.kind).toBe(RbiV2PacketKind.DatagramPointer);
    if (decodedPointer.kind === RbiV2PacketKind.DatagramPointer) {
      expect(decodedPointer.datagram.seq).toBe(15);
      expect(decodedPointer.datagram.x).toBe(30);
    }

    // Inbound client datagrams coalesce latest-wins too.
    client.sendLatestDatagram({
      kind: "scroll",
      seq: 8,
      scrollNodeId: 2n,
      x: 5,
      y: 90,
      velX: 0,
      velY: 400,
    });
    client.sendLatestDatagram({
      kind: "scroll",
      seq: 12,
      scrollNodeId: 2n,
      x: 10,
      y: 220,
      velX: 0,
      velY: 950,
    });
    client.sendLatestDatagram({
      kind: "scroll",
      seq: 9,
      scrollNodeId: 2n,
      x: 0,
      y: 0,
      velX: 0,
      velY: 0,
    });
    const latestInbound = server.takeLatestInboundScroll(2n);
    expect(latestInbound?.seq).toBe(12);
    expect(latestInbound?.y).toBe(220);

    // Grant credits via binary CREDIT_GRANT packet to drain remaining reliable frames.
    client.acknowledgeFrame(1, 1);
    expect(reliableSent.length).toBe(3);
    expect(server.stats().queuedReliableFrames).toBe(1);
    client.acknowledgeFrame(2, 2);
    expect(reliableSent.length).toBe(4);
    expect(server.stats().queuedReliableFrames).toBe(0);
    const frame3 = decodeRbiV2Packet(reliableSent[2]!);
    expect(frame3.kind).toBe(RbiV2PacketKind.ReliableFrame);
    if (frame3.kind === RbiV2PacketKind.ReliableFrame) {
      expect(frame3.frameSeq).toBe(3);
    }
  });

  it("performs reattachWithTileHashes delta resync during 100ms RTT fling", () => {
    // 16 vertical tiles covering y = [0..4096).
    const allTiles: IndexedTileV2[] = [];
    for (let row = 0; row < 16; row++) {
      allTiles.push(makeIndexedTile(row + 1, 0, row * 256, 800, 256));
    }

    const clientDownstream: Uint8Array[] = [];
    const server = new RbiV2ServerChannel(
      { sendReliable: (pkt) => clientDownstream.push(pkt) },
      {
        initialCredits: 4,
        onReattachResync: ({ lastFrameSeq, knownTileHashes, interestRect }) => {
          const { deltaTiles, prunedKnown } = selectDeltaTilesForClient(
            allTiles,
            interestRect,
            knownTileHashes,
          );
          const payload = new Uint8Array(deltaTiles.length * 512);
          let off = 0;
          for (const t of deltaTiles) {
            payload.set(t.encodedBytes, off);
            off += t.encodedBytes.byteLength;
          }
          return {
            resumedFromSeq: lastFrameSeq,
            prunedKnownTiles: prunedKnown,
            payload,
          };
        },
      },
    );

    const client = new RbiV2ClientChannel({
      sendReliable: (pkt) => server.handleClientPacket(pkt),
    });

    // At 100ms RTT, client scrolls y: 600 -> 856 while caching overscan rows 0..9.
    const cachedHashes = allTiles.slice(0, 10).map((t) => t.contentHash);
    client.registerKnownTiles(cachedHashes);
    client.acknowledgeFrame(11, 1);

    const interest = computeInterestRectV2({ x: 0, y: 600, w: 800, h: 600 }, 0, 2000);
    expect(interest.y).toBe(0);
    expect(interest.h).toBe(2400);

    const reattachBytes = client.reattachWithTileHashes({ x: 0, y: 600, w: 800, h: 600 }, 0, 2000);
    expect(reattachBytes).toBeInstanceOf(Uint8Array);
    expect(clientDownstream.length).toBe(1);

    const ack = decodeRbiV2Packet(clientDownstream[0]!);
    expect(ack.kind).toBe(RbiV2PacketKind.DeltaResyncAck);
    if (ack.kind === RbiV2PacketKind.DeltaResyncAck) {
      expect(ack.resumedFromSeq).toBe(11);
      // Rows 0..9 already cached by client -> 10 tiles pruned, rows 10..15 culled outside 2400!
      expect(ack.prunedKnownTiles).toBe(10);
      expect(ack.payload.byteLength).toBe(0);
    }

    // Fling further down past y=1800 -> misses only newly entering rows 10..12, skipping 0..9.
    client.reattachWithTileHashes({ x: 0, y: 1800, w: 800, h: 600 }, 0, 1500);
    const secondAck = decodeRbiV2Packet(clientDownstream[1]!);
    expect(secondAck.kind).toBe(RbiV2PacketKind.DeltaResyncAck);
    if (secondAck.kind === RbiV2PacketKind.DeltaResyncAck) {
      const uncachedBytes = allTiles.length * 512;
      expect(secondAck.prunedKnownTiles).toBeGreaterThan(0);
      expect(secondAck.payload.byteLength).toBeLessThan(uncachedBytes);
    }

    const roundtripAck = encodeDeltaResyncAckPacket({
      resumedFromSeq: 5,
      prunedKnownTiles: 3,
      payload: new Uint8Array([9, 8, 7]),
    });
    const decodedAck = decodeRbiV2Packet(roundtripAck);
    expect(decodedAck.kind).toBe(RbiV2PacketKind.DeltaResyncAck);
    const decodedReattach = decodeRbiV2Packet(
      encodeReattachWithTileHashesPacket(9, [1n, 2n], { x: 0, y: 0, w: 800, h: 600 }, 0, 0),
    );
    expect(decodedReattach.kind).toBe(RbiV2PacketKind.ReattachWithTileHashes);
    expect(
      encodeDatagramPacket({ kind: "pointer", seq: 1, x: 2, y: 3, buttons: 0 }),
    ).toBeInstanceOf(Uint8Array);
  });
});

describe("HandlerRegionTracker", () => {
  it("tracks non-passive wheel and touch regions, scroll ancestors, and reset", () => {
    const tracker = new handlerRegionsMod.HandlerRegionTracker();
    // Passive listeners never block compositor scroll.
    tracker.recordMutation(10, "wheel", true, true);
    tracker.recordMutation(11, "touchstart", true, true);
    expect(tracker.activeMasks().size).toBe(0);

    // Non-passive listeners on doc (id=1), scroll container (id=20), child (id=21), detached (99).
    tracker.recordMutation(1, "wheel", false, true);
    tracker.recordMutation(21, "touchstart", false, true);
    tracker.recordMutation(21, "touchmove", false, true);
    tracker.recordMutation(99, "wheel", false, true);

    const parents = new Map<number, number>([
      [20, 1],
      [21, 20],
      [99, -1],
    ]);
    const regions = tracker.snapshotRegions({
      documentNodeId: 1,
      viewportWidth: 800,
      viewportHeight: 600,
      getBoundingRect: (id) =>
        id === 20
          ? { x: 0, y: 0, width: 400, height: 300 }
          : id === 21
            ? { x: 40, y: 120, width: 300, height: 180 }
            : null,
      getScrollInfo: (id) =>
        id === 20
          ? { clientWidth: 400, clientHeight: 300, scrollWidth: 400, scrollHeight: 1600 }
          : id === 1
            ? { clientWidth: 800, clientHeight: 600, scrollWidth: 800, scrollHeight: 1200 }
            : { clientWidth: 300, clientHeight: 180, scrollWidth: 300, scrollHeight: 180 },
      parentNodeId: (id) => parents.get(id) ?? -1,
    });

    expect(regions.length).toBe(2);
    expect(regions[0]).toEqual({
      targetNodeId: 1,
      scrollNodeId: 1,
      x: 0,
      y: 0,
      width: 800,
      height: 1200,
      eventMask: handlerRegionsMod.HANDLER_WHEEL,
      nonPassive: true,
      coversScrollNode: true,
    });
    expect(regions[1]).toEqual({
      targetNodeId: 21,
      scrollNodeId: 20,
      x: 40,
      y: 120,
      width: 300,
      height: 180,
      eventMask: handlerRegionsMod.HANDLER_TOUCH_START | handlerRegionsMod.HANDLER_TOUCH_MOVE,
      nonPassive: true,
      coversScrollNode: false,
    });

    // DocumentElement and direct scroll-container listeners set coversScrollNode=true.
    tracker.recordMutation(2, "wheel", false, true);
    tracker.recordMutation(20, "wheel", false, true);
    const parentWithHtml = new Map<number, number>([
      [2, 1],
      [20, 2],
      [21, 20],
    ]);
    const docElRegions = tracker.snapshotRegions({
      documentNodeId: 1,
      documentElementNodeId: 2,
      viewportWidth: 800,
      viewportHeight: 600,
      getBoundingRect: (id) =>
        id === 20
          ? { x: 0, y: 0, width: 400, height: 300 }
          : id === 21
            ? { x: 40, y: 120, width: 300, height: 180 }
            : null,
      getScrollInfo: (id) =>
        id === 20
          ? { clientWidth: 400, clientHeight: 300, scrollWidth: 400, scrollHeight: 1600 }
          : id === 2
            ? { clientWidth: 800, clientHeight: 600, scrollWidth: 800, scrollHeight: 1600 }
            : null,
      parentNodeId: (id) => parentWithHtml.get(id) ?? -1,
    });
    expect(docElRegions.find((r) => r.targetNodeId === 2)?.coversScrollNode).toBe(true);
    expect(docElRegions.find((r) => r.targetNodeId === 20)?.coversScrollNode).toBe(true);
    expect(docElRegions.find((r) => r.targetNodeId === 21)?.coversScrollNode).toBe(false);
    tracker.recordMutation(2, "wheel", false, false);
    tracker.recordMutation(20, "wheel", false, false);

    // Reference-counted remove leaves touchstart until both touchstart & touchmove removed.
    tracker.recordMutation(21, "touchmove", false, false);
    const updated = tracker.snapshotRegions({
      documentNodeId: 1,
      viewportWidth: 800,
      viewportHeight: 600,
      getBoundingRect: (id) =>
        id === 20
          ? { x: 0, y: 0, width: 400, height: 300 }
          : id === 21
            ? { x: 40, y: 120, width: 300, height: 180 }
            : null,
      getScrollInfo: () => null,
      parentNodeId: (id) => parents.get(id) ?? -1,
    });
    expect(updated[1]!.eventMask).toBe(handlerRegionsMod.HANDLER_TOUCH_START);
    expect(updated[1]!.scrollNodeId).toBe(1);

    tracker.reset();
    expect(tracker.activeMasks().size).toBe(0);
  });
});

describe("8.8 ClientInputJournal AES-256-GCM", () => {
  const safeField: StableFieldKey = {
    origin: "https://app.example",
    formId: "compose-form",
    tagName: "TEXTAREA",
    fieldName: "message_body",
    fieldId: "msg",
    domPath: "html>body>form#compose-form>textarea#msg",
  };

  it("encrypts entries with AES-256-GCM AAD, hides plaintext, and replays unacked inputs", async () => {
    const journal = await ClientInputJournal.create();
    const secretText = "Meet me at café 42 on Tuesday";

    const r1 = await journal.recordInput({
      inputSeq: 1,
      field: safeField,
      value: "Meet",
      selectionStart: 4,
      selectionEnd: 4,
    });
    const r2 = await journal.recordInput({
      inputSeq: 2,
      field: safeField,
      value: secretText,
      selectionStart: secretText.length,
      selectionEnd: secretText.length,
    });
    expect(r1.recorded).toBe(true);
    expect(r2.recorded).toBe(true);

    // Ciphertext must never contain raw UTF-8 input and must use unique IVs.
    const snap = journal.encryptedSnapshot();
    expect(snap.length).toBe(2);
    const rawNeedle = new TextEncoder().encode("café 42");
    for (const rec of snap) {
      const hex = Buffer.from(rec.ciphertext).toString("hex");
      expect(hex.includes(Buffer.from(rawNeedle).toString("hex"))).toBe(false);
    }
    expect(Buffer.from(snap[0]!.iv).equals(Buffer.from(snap[1]!.iv))).toBe(false);

    // Ack seq 1 -> drops seq 1 and zeroes its ciphertext/iv buffers.
    const dropped = journal.acknowledgeServerSeq(1);
    expect(dropped).toBe(1);
    expect(snap[0]!.iv.every((b) => b === 0)).toBe(true);
    expect(snap[0]!.ciphertext.every((b) => b === 0)).toBe(true);

    // Cross-origin replay returns nothing; same-origin replays only seq 2 in order.
    expect(await journal.replayUnacked("https://other.example")).toEqual([]);
    const replayed = await journal.replayUnacked("https://app.example");
    expect(replayed.length).toBe(1);
    expect(replayed[0]!.inputSeq).toBe(2);
    expect(replayed[0]!.value).toBe(secretText);
    expect(replayed[0]!.field.fieldId).toBe("msg");
    expect(canonicalFieldKey(replayed[0]!.field)).toBe(canonicalFieldKey(safeField));
  });

  it("rejects AES-GCM AAD or ciphertext tampering", async () => {
    const keyBytes = new Uint8Array(32).fill(0x5a);
    const journal = await ClientInputJournal.create(keyBytes);
    await journal.recordInput({ inputSeq: 5, field: safeField, value: "tamper check" });
    const snap = journal.encryptedSnapshot();
    expect(snap.length).toBe(1);
    snap[0]!.ciphertext[0] = (snap[0]!.ciphertext[0]! ^ 0xff) & 0xff;
    await expect(journal.replayUnacked("https://app.example")).rejects.toThrow();
  });

  it("strictly rejects password, credential, payment card, OTP, hidden, and submit inputs", async () => {
    const journal = await ClientInputJournal.create();
    const sensitiveCases: Array<{ label: string; field: StableFieldKey; submit?: boolean }> = [
      {
        label: "password type",
        field: { origin: "https://a.test", tagName: "INPUT", inputType: "password" },
      },
      {
        label: "current-password autocomplete",
        field: {
          origin: "https://a.test",
          tagName: "INPUT",
          inputType: "text",
          autocomplete: "current-password",
        },
      },
      {
        label: "username autocomplete",
        field: {
          origin: "https://a.test",
          tagName: "INPUT",
          inputType: "text",
          autocomplete: "username",
        },
      },
      {
        label: "webauthn credential",
        field: {
          origin: "https://a.test",
          tagName: "INPUT",
          inputType: "text",
          autocomplete: "webauthn",
        },
      },
      {
        label: "csrf token field name",
        field: {
          origin: "https://a.test",
          tagName: "INPUT",
          inputType: "text",
          fieldName: "csrf_token",
        },
      },
      {
        label: "cc-number autocomplete",
        field: {
          origin: "https://a.test",
          tagName: "INPUT",
          inputType: "text",
          autocomplete: "cc-number",
        },
      },
      {
        label: "cvv name",
        field: {
          origin: "https://a.test",
          tagName: "INPUT",
          inputType: "tel",
          fieldName: "card_cvv",
        },
      },
      {
        label: "one-time-code autocomplete",
        field: {
          origin: "https://a.test",
          tagName: "INPUT",
          inputType: "text",
          autocomplete: "one-time-code",
        },
      },
      {
        label: "totp id",
        field: {
          origin: "https://a.test",
          tagName: "INPUT",
          inputType: "text",
          fieldId: "mfa_totp",
        },
      },
      {
        label: "hidden field",
        field: { origin: "https://a.test", tagName: "INPUT", inputType: "hidden" },
      },
      {
        label: "submit input type",
        field: { origin: "https://a.test", tagName: "INPUT", inputType: "submit" },
      },
      {
        label: "explicit submit action flag",
        field: safeField,
        submit: true,
      },
    ];

    for (let i = 0; i < sensitiveCases.length; i++) {
      const tc = sensitiveCases[i]!;
      const res = await journal.recordInput({
        inputSeq: i + 1,
        field: tc.field,
        value: "secret-123",
        isSubmitAction: tc.submit,
      });
      expect(res.recorded, tc.label).toBe(false);
    }
    expect(journal.size()).toBe(0);
    expect(classifyFieldSensitivity(safeField).sensitive).toBe(false);
  });

  it("clears and zeroes encrypted records on form submit and navigation", async () => {
    const journal = await ClientInputJournal.create();
    const otherFormField: StableFieldKey = {
      origin: "https://app.example",
      formId: "search-form",
      tagName: "INPUT",
      inputType: "search",
      fieldName: "q",
    };
    await journal.recordInput({ inputSeq: 1, field: safeField, value: "draft message" });
    await journal.recordInput({ inputSeq: 2, field: otherFormField, value: "parawing" });

    const snapBefore = journal.encryptedSnapshot();
    const clearedSubmit = journal.clearOnSubmit({
      origin: "https://app.example",
      formId: "compose-form",
    });
    expect(clearedSubmit).toBe(1);
    expect(snapBefore[0]!.ciphertext.every((b) => b === 0)).toBe(true);
    expect(journal.size()).toBe(1);

    const remaining = await journal.replayUnacked("https://app.example");
    expect(remaining.length).toBe(1);
    expect(remaining[0]!.field.formId).toBe("search-form");

    const clearedNav = journal.clearOnNavigation(true);
    expect(clearedNav).toBe(1);
    expect(snapBefore[1]!.ciphertext.every((b) => b === 0)).toBe(true);
    expect(journal.size()).toBe(0);
    expect(await journal.replayUnacked("https://app.example")).toEqual([]);
  });

  it("extracts KSC2 tile count, hashes, and invalidated hashes accurately", () => {
    const chunks: number[] = [];
    const pushU8 = (v: number): void => {
      chunks.push(v & 0xff);
    };
    const pushU32 = (v: number): void => {
      const b = new ArrayBuffer(4);
      new DataView(b).setUint32(0, v >>> 0, true);
      chunks.push(...new Uint8Array(b));
    };
    const pushU64 = (v: bigint): void => {
      const b = new ArrayBuffer(8);
      new DataView(b).setBigUint64(0, BigInt.asUintN(64, v), true);
      chunks.push(...new Uint8Array(b));
    };
    const pushF32 = (v: number): void => {
      const b = new ArrayBuffer(4);
      new DataView(b).setFloat32(0, v, true);
      chunks.push(...new Uint8Array(b));
    };
    const pushF64 = (v: number): void => {
      const b = new ArrayBuffer(8);
      new DataView(b).setFloat64(0, v, true);
      chunks.push(...new Uint8Array(b));
    };
    const pushRect = (x: number, y: number, w: number, h: number): void => {
      pushF32(x);
      pushF32(y);
      pushF32(w);
      pushF32(h);
    };

    chunks.push(0x4b, 0x53, 0x43, 0x32);
    pushU32(1);
    pushU32(10);
    pushU32(20);
    pushU32(800);
    pushU32(600);

    // 1 scroll node with 1 X snap point.
    pushU32(1);
    pushU64(0n);
    pushU64(0n);
    pushF32(800);
    pushF32(1200);
    pushRect(0, 0, 800, 600);
    pushF32(0);
    pushF32(0);
    pushU32(1);
    pushF32(400);
    pushU32(0);
    pushU8(0);
    pushU8(0);
    pushU8(0);
    pushU8(0);

    // 1 sticky layer with 1 animation, 2 tile_refs, and 1 invalidated hash.
    pushU32(1);
    pushU64(1n);
    pushU64(0n);
    pushU8(2);
    pushRect(0, 10, 100, 20);
    pushRect(0, 0, 800, 600);
    pushU8(1);
    pushF32(10);
    pushU8(0);
    pushU8(0);
    pushU8(0);
    pushRect(0, 0, 800, 600);
    pushU8(255);
    pushU8(255);
    pushU8(255);
    pushU8(255);
    pushF32(1);
    for (const m of [1, 0, 0, 1, 0, 0]) pushF32(m);
    pushU32(1);
    pushU8(0);
    pushF64(0);
    pushF64(500);
    pushF32(1);
    pushU8(1);
    pushU32(1);
    pushF32(0);
    pushU8(0);
    pushF32(0.5);
    pushU8(2);
    pushF32(0.1);
    pushF32(0.2);
    pushF32(0.3);
    pushF32(0.4);
    pushU32(256);
    pushU32(2);
    for (const [col, h] of [
      [0, 0xaa01n],
      [1, 0xbb02n],
    ] as const) {
      pushU32(col);
      pushU32(0);
      pushRect(col * 256, 0, 256, 256);
      pushU64(h);
    }
    pushU32(1);
    pushU64(0xdead_beefn);

    // 2 TilePayloadV2 entries (first includes 1 text_run and 1 hit_rect with link_url).
    pushU32(2);
    pushU64(0xaa01n);
    pushU32(256);
    pushU32(256);
    pushU32(3);
    pushU8(1);
    pushU8(2);
    pushU8(3);
    pushU32(1);
    pushU64(7n);
    pushU32(2);
    pushU8(0x68);
    pushU8(0x69);
    pushU64(55n);
    pushF32(16);
    pushU8(0);
    pushF32(0);
    pushF32(0);
    pushF32(12);
    pushF32(4);
    pushU32(0);
    pushU32(1);
    pushRect(0, 0, 100, 20);
    pushU64(7n);
    pushU64(0n);
    pushU8(1);
    pushU8(1);
    pushU32(1);
    pushU8(0x2f);
    pushU8(0);
    pushU8(1);

    pushU64(0xbb02n);
    pushU32(256);
    pushU32(256);
    pushU32(0);
    pushU32(0);
    pushU32(0);

    const bytes = new Uint8Array(chunks);
    const meta = extractKsc2TileMetadata(bytes);
    expect(meta.tileCount).toBe(2);
    expect(meta.tileHashes).toEqual([0xaa01n, 0xbb02n]);
    expect(meta.invalidatedHashes).toEqual([0xdead_beefn]);

    const shortMeta = extractKsc2TileMetadata(new Uint8Array([0x4b, 0x53, 0x43, 0x32, 1, 0, 0, 0]));
    expect(shortMeta).toEqual({ tileCount: 0, tileHashes: [], invalidatedHashes: [] });
  });
});
