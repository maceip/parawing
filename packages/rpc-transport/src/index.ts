// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Re-exports PRWP framing, capability tables, and RpcSession transport APIs.

export {
  DEFAULT_MAX_PAYLOAD_BYTES,
  FrameDecoder,
  FrameFlag,
  FrameType,
  PRWP_HEADER_BYTES,
  PRWP_MAGIC,
  PRWP_VERSION,
  decodeHeader,
  encodeFrame,
  isValidFrameType,
  type FrameHeader,
  type FrameTypeCode,
  type RpcFrame,
} from "./framing.ts";

export {
  CapabilityTable,
  RPC_TARGET_SYMBOL,
  isRpcTargetObject,
  markRpcTarget,
  type CapabilityDispatch,
  type EncodedPayload,
  type WireCapKind,
} from "./capabilities.ts";

export {
  RpcSession,
  bindSignal,
  createRpcSession,
  createStreamPair,
  currentCallSignal,
  isPackedException,
  packException,
  unpackException,
  withCallSignal,
  type BidirectionalStreamPair,
  type RpcCallOptions,
  type RpcHandlerContext,
  type RpcSessionOptions,
  type RpcSessionStats,
  type RpcTransportState,
} from "./session.ts";
