// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import type { Protocol } from "devtools-protocol";
import type {
  BoaCollectStats as PageScriptBoaCollectStats,
  FontFaces as PageScriptFontFaces,
  HandlerRegionInfo,
  PageScriptGauges,
} from "@parawing/jsrpc-types/query-dom";
import "devtools-protocol/types/protocol-mapping";

declare module "devtools-protocol" {
  namespace Protocol {
    namespace DOM {
      interface GetOuterHTMLRequest {
        includeDoctype?: boolean;
      }
      interface QuerySelectorResponse {
        error?: string;
      }
    }
    namespace Page {
      interface CaptureScreenshotRequest {
        omitBackground?: boolean;
      }
      interface PrintToPDFRequest {
        omitBackground?: boolean;
      }
      interface PrintToPDFResponse {
        error?: string;
      }
      interface SetDocumentContentResponse {
        error?: string;
      }
      interface NavigateRequest {
        _parawingInternal?: boolean;
        _parawingPostData?: string;
        _parawingPostContentType?: string;
        _parawingLoaderId?: string;
        _parawingRequireApproval?: boolean;
        _parawingApprovalDecision?: unknown;
        _parawingApprovalNonce?: string;
        _parawingApprovalTimeoutMs?: number;
        /**
         * Origin of the document that initiated a page-started navigation. Absent for a
         * browser/CDP-started navigation; the literal "null" for an opaque page initiator.
         */
        _parawingInitiatorOrigin?: string;
      }
      interface StartScreencastRequest {
        minFrameIntervalMs?: integer;
        maxInFlight?: integer;
        maxFramesInFlight?: integer;
      }
    }

    namespace Parawing {
      type LayoutMode = "full" | "off";

      interface TargetScopedRequest {
        targetId?: Target.TargetID;
      }

      /** Reply of the per-target methods that fan out without a `targetId`. */
      interface ByTargetResponse<T> {
        byTarget: Record<Target.TargetID, T | null>;
      }

      interface SceneRect {
        x: number;
        y: number;
        w: number;
        h: number;
      }

      interface StartSceneStreamRequest extends TargetScopedRequest {
        width: integer;
        height: integer;
        fps?: integer;
        text?: boolean;
        terminal?: boolean;
        cellW?: number;
        cellH?: number;
        allowPartial?: boolean;
      }

      interface SceneFrameAckRequest extends TargetScopedRequest {
        seq: integer;
        painted?: boolean;
      }

      interface GetSceneResourcesRequest extends TargetScopedRequest {
        missingB64: string;
      }

      interface GetSceneResourcesResponse {
        batchB64: string;
      }

      interface SceneHostManifest {
        abi: integer;
        wireVersion: integer;
        wasm: "scene_host.wasm";
        sha256: string;
        bytes: integer;
        retainedFrames?: boolean;
      }

      interface ReadSceneHostRequest {
        sha256: string;
        offset: integer;
        /** Raw bytes, between 1 and 4194304. The last chunk may be shorter. */
        length: integer;
      }

      interface ReadSceneHostResponse {
        sha256: string;
        offset: integer;
        totalBytes: integer;
        dataB64: string;
      }

      interface SceneFrameEvent {
        data: string;
      }

      interface GetSessionInfoResponse {
        sessionId: string;
        entrypoint: string;
        connectionMode: "page" | "browser";
        environment: string;
        buildVersion: string;
        colo: string;
        persistentSessionId?: string | null;
        userId?: string | null;
        epoch?: number | null;
        connectionRole?: "owner" | "viewer" | null;
        delegatedAgent?: boolean;
      }

      interface SetLayoutModeRequest extends TargetScopedRequest {
        mode?: string;
      }

      type SetLayoutModeResponse =
        | { mode: LayoutMode; scope: "browser"; targets: Target.TargetID[] }
        | {
            mode: LayoutMode;
            scope: "target";
            targetId: Target.TargetID;
            error?: string;
          };

      interface GetLayoutModeResponse {
        mode: string;
        error?: string;
      }

      interface GetRendererInfoResponse {
        enabled: boolean;
        active: boolean;
        framesRendered: number;
        partialFramesRendered: number;
        relaunchCount: number;
        rendererWasmBytes: number | null;
        rendererWasmDeltaBytes: number | null;
        initialRes: string | null;
        partialRaster: boolean;
      }

      interface SetPartialRasterRequest {
        enabled?: boolean;
      }

      interface SetPartialRasterResponse {
        enabled: boolean;
      }

      interface DisposeRendererResponse {
        disposed: boolean;
      }

      type NavigatePhases = Record<string, number>;

      type GetNavigatePhasesResponse =
        | ByTargetResponse<NavigatePhases>
        | { phases: NavigatePhases | null; error?: string };

      interface PendingCriticalResources {
        pending: boolean;
        error?: string;
      }

      type HasPendingCriticalResourcesResponse =
        | ByTargetResponse<PendingCriticalResources>
        | PendingCriticalResources
        | Record<string, never>;

      /** Page position and the DOM mutation counter, read without a full DOM walk. */
      interface GetPageStateResponse {
        /** Increments on every DOM mutation; compare two reads to detect a change. */
        seq?: integer;
        scrollX?: number;
        scrollY?: number;
        href?: string;
        title?: string;
        error?: string;
      }

      interface SetControlValueRequest extends TargetScopedRequest {
        /** A `DOM.NodeId` from the current document. */
        nodeId: DOM.NodeId;
        /** A string, a boolean for a checkbox or radio, or strings for `<select multiple>`. */
        value: unknown;
      }

      interface SetControlValueResponse {
        changed: boolean;
        /** The control's `value` after the write. */
        value?: string;
        error?: string;
      }

      interface MarkPaintDamageResponse {
        error?: string;
      }

      interface GetPaintDamageSinceRequest extends TargetScopedRequest {
        /**
         * Leave out this node, its subtree and its ancestors, such as the control a client just
         * used, whose hover and focus restyle would otherwise always show.
         */
        excludeNodeId?: DOM.NodeId;
      }

      interface GetPaintDamageSinceResponse {
        /** Nodes whose painted output changed since `Parawing.markPaintDamage`. */
        nodeIds: DOM.NodeId[];
        /** More nodes changed than the report holds. */
        overflow: boolean;
        error?: string;
      }

      interface MemoryStats extends PageScriptGauges {
        wasmBytes?: number;
        wasmInitialBytes?: number;
        wasmDeltaBytes?: number;
        frameWasmBytes?: number;
        frameWasmDeltaBytes?: number;
      }

      interface GetMemoryStatsResponse extends MemoryStats {
        byTarget?: Record<Target.TargetID, MemoryStats | null>;
        engine?: {
          wasmBytes: number;
          wasmInitialBytes: number;
          wasmDeltaBytes: number;
          retainedBodyBytes: number;
          retainedBodyBytesIsolate: number;
          retainedRequestCount: number;
          retainedImageBytes: number;
          retainedImageCount: number;
          fontAssetCacheBytes: number;
          accountedBytes: number;
        };
        renderer?: {
          wasmBytes: number;
          wasmInitialBytes: number;
          wasmDeltaBytes: number;
        };
        isolatesKilled?: number;
        total?: {
          bytes: number;
          deltaBytes: number;
          engineBytes: number;
          pageScriptBytes: number;
          rendererBytes: number;
        };
      }

      // Patterns are JS RegExp syntax, non-unicode and flagless. Lookaround, backreferences,
      // octal escapes, repeats over 1000 and expansions past 8192 steps are refused, and at most
      // 32 patterns of 500 chars each are accepted. One refused pattern rejects the call and
      // keeps the previous filters. Cost is linear in URL x pattern size; URLs are unbounded.
      interface SetOutboundFiltersRequest {
        allowRequestPattern?: string[];
        rejectRequestPattern?: string[];
        allowResourceTypes?: string[];
        rejectResourceTypes?: string[];
      }

      type SetOutboundFiltersResponse = { ok: true } | { ok: false; error: string };

      interface RecordSceneRequest extends TargetScopedRequest {
        producer?: "client" | "replay";
        sinceSeq?: integer;
        omitBackground?: boolean;
        inlineResources?: boolean;
        clip?: {
          x: number;
          y: number;
          width: number;
          height: number;
          scale?: number;
        };
        allowPartial?: boolean;
        allowScrollShift?: boolean;
        baseSeq?: integer;
        pumpRaf?: boolean;
        frameIntervalMs?: number;
      }

      interface RecordedScene {
        sceneB64: string;
        resourceBatchB64: string;
        seq: integer;
        unchanged: boolean;
        partial: boolean;
        clip: SceneRect | null;
        baseSeq: integer;
        scrollX: number;
        scrollY: number;
        damageCount: integer;
        layoutDirty: boolean;
        skipReason: string;
        error?: string;
      }

      type RecordSceneResponse = RecordedScene | { error: string };

      interface GetRbiResourcesRequest extends TargetScopedRequest {
        missingB64?: string;
      }

      type GetRbiResourcesResponse = { batchB64: string; error?: string } | { error: string };

      interface GetScreencastStatusResponse {
        active?: boolean;
        framesDropped?: integer;
        lastError?: string;
        inFlight?: integer;
        targetId?: Target.TargetID;
        targetUrl?: string;
        hasPageScript?: boolean;
        generation?: integer;
        pageTargets?: integer;
        error?: string;
      }

      interface GetConnectionInfoResponse {
        connectionId: string;
      }

      interface StartSceneStreamV2Request extends TargetScopedRequest {
        width?: integer;
        height?: integer;
        fps?: integer;
        initialCredits?: integer;
        maxCredits?: integer;
      }

      interface StartSceneStreamV2Response {
        wsPath?: string;
        token?: string;
        ackedScrollSeq?: integer;
        ackedInputSeq?: integer;
        journalSize?: integer;
        error?: string;
      }

      interface StopSceneStreamV2Response {
        stats?: {
          availableCredits: integer;
          maxCredits: integer;
          sentReliableFrames: integer;
          queuedReliableFrames: integer;
          sentDatagrams: integer;
          coalescedDatagrams: integer;
          reattachCount: integer;
          prunedKnownTilesTotal: integer;
        } | null;
        error?: string;
      }

      interface RecordSceneV2Request extends TargetScopedRequest {
        knownHashesB64?: string;
        velX?: number;
        velY?: number;
        pumpRaf?: boolean;
      }

      interface RecordSceneV2Response {
        frameB64: string;
        seq: integer;
        scrollX: number;
        scrollY: number;
        origin: string;
        ackedScrollSeq: integer;
        ackedInputSeq: integer;
        handlerRegions: HandlerRegionInfo[];
        error?: string;
      }

      interface GetHandlerRegionsResponse {
        regions: HandlerRegionInfo[];
        error?: string;
      }

      interface GetInputJournalStateRequest extends TargetScopedRequest {
        acknowledgeSeq?: integer;
        includeEncryptedSnapshot?: boolean;
        replay?: boolean;
      }

      interface GetInputJournalStateResponse {
        size?: integer;
        encryptedCount?: integer;
        nextInputSeq?: integer;
        ackedInputSeq?: integer;
        lastRejectionReason?: string;
        replayedCount?: integer;
        origin?: string;
        error?: string;
      }

      type PageDiagnosticResponse<T extends { error?: string }> = ByTargetResponse<T> | T;

      type FontFaces = PageScriptFontFaces;
      type BoaCollectStats = PageScriptBoaCollectStats;

      type OpaqueDiagnostic = Record<string, unknown> & { error?: string };

      interface DestroySessionRequest {
        sessionId?: string;
      }

      interface DestroySessionResponse {
        destroyed: boolean;
        sessionId: string;
      }

      interface SessionRestoredEvent {
        readonly sessionId: string;
        readonly userId: string;
        readonly reason: string;
        readonly checkpointTakenAt: number;
        readonly targets: ReadonlyArray<{
          readonly targetId: string;
          readonly generation: number;
          readonly url: string;
          readonly restoreMethod: "GET";
          readonly pendingUnsafeNavigationUrl: string | null;
        }>;
        readonly replayedInputSeqs: ReadonlyArray<number>;
      }
    }
  }
}

declare module "devtools-protocol/types/protocol-mapping" {
  namespace ProtocolMapping {
    interface Events {
      "Parawing.sceneFrame": [Protocol.Parawing.SceneFrameEvent];
      "Parawing.sessionRestored": [Protocol.Parawing.SessionRestoredEvent];
      "Parawing.sessionAttached": [Record<string, unknown>];
      "Parawing.sessionSuspended": [Record<string, unknown>];
      "Parawing.sessionResumed": [Record<string, unknown>];
      "Parawing.sessionRoamed": [Record<string, unknown>];
      "Parawing.sessionDestroyed": [Record<string, unknown>];
      "Parawing.approvalRequired": [Record<string, unknown>];
    }

    interface Commands {
      "Parawing.startSceneStream": {
        paramsType: [Protocol.Parawing.StartSceneStreamRequest];
        returnType: void;
      };
      "Parawing.stopSceneStream": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: void;
      };
      "Parawing.sceneFrameAck": {
        paramsType: [Protocol.Parawing.SceneFrameAckRequest];
        returnType: void;
      };
      "Parawing.getSceneResources": {
        paramsType: [Protocol.Parawing.GetSceneResourcesRequest];
        returnType: Protocol.Parawing.GetSceneResourcesResponse;
      };
      "Parawing.getSceneHostManifest": {
        paramsType: [];
        returnType: Protocol.Parawing.SceneHostManifest;
      };
      "Parawing.readSceneHost": {
        paramsType: [Protocol.Parawing.ReadSceneHostRequest];
        returnType: Protocol.Parawing.ReadSceneHostResponse;
      };
      "Parawing.getSessionInfo": {
        paramsType: [];
        returnType: Protocol.Parawing.GetSessionInfoResponse;
      };
      "Parawing.setLayoutMode": {
        paramsType: [Protocol.Parawing.SetLayoutModeRequest?];
        returnType: Protocol.Parawing.SetLayoutModeResponse;
      };
      "Parawing.getLayoutMode": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.GetLayoutModeResponse;
      };
      "Parawing.getRendererInfo": {
        paramsType: [];
        returnType: Protocol.Parawing.GetRendererInfoResponse;
      };
      "Parawing.setPartialRaster": {
        paramsType: [Protocol.Parawing.SetPartialRasterRequest?];
        returnType: Protocol.Parawing.SetPartialRasterResponse;
      };
      "Parawing.disposeRenderer": {
        paramsType: [];
        returnType: Protocol.Parawing.DisposeRendererResponse;
      };
      "Parawing.getNavigatePhases": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.GetNavigatePhasesResponse;
      };
      "Parawing.hasPendingCriticalResources": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.HasPendingCriticalResourcesResponse;
      };
      "Parawing.getPageState": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.GetPageStateResponse;
      };
      "Parawing.setControlValue": {
        paramsType: [Protocol.Parawing.SetControlValueRequest];
        returnType: Protocol.Parawing.SetControlValueResponse;
      };
      "Parawing.markPaintDamage": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.MarkPaintDamageResponse;
      };
      "Parawing.getPaintDamageSince": {
        paramsType: [Protocol.Parawing.GetPaintDamageSinceRequest?];
        returnType: Protocol.Parawing.GetPaintDamageSinceResponse;
      };
      "Parawing.getMemoryStats": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.GetMemoryStatsResponse;
      };
      "Parawing.setOutboundFilters": {
        paramsType: [Protocol.Parawing.SetOutboundFiltersRequest?];
        returnType: Protocol.Parawing.SetOutboundFiltersResponse;
      };
      "Parawing.recordScene": {
        paramsType: [Protocol.Parawing.RecordSceneRequest?];
        returnType: Protocol.Parawing.RecordSceneResponse;
      };
      "Parawing.getScreencastStatus": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.GetScreencastStatusResponse;
      };
      "Parawing.getConnectionInfo": {
        paramsType: [];
        returnType: Protocol.Parawing.GetConnectionInfoResponse;
      };
      "Parawing.getRbiResources": {
        paramsType: [Protocol.Parawing.GetRbiResourcesRequest?];
        returnType: Protocol.Parawing.GetRbiResourcesResponse;
      };
      "Parawing.getFontFaces": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.PageDiagnosticResponse<Protocol.Parawing.FontFaces>;
      };
      "Parawing.boaForceCollect": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.PageDiagnosticResponse<Protocol.Parawing.BoaCollectStats>;
      };
      "Parawing.getMemprofDump": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.PageDiagnosticResponse<Protocol.Parawing.OpaqueDiagnostic>;
      };
      "Parawing.resetMemprof": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.PageDiagnosticResponse<Protocol.Parawing.OpaqueDiagnostic>;
      };
      "Parawing.getSceneStats": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.PageDiagnosticResponse<Protocol.Parawing.OpaqueDiagnostic>;
      };
      "Parawing.destroySession": {
        paramsType: [Protocol.Parawing.DestroySessionRequest?];
        returnType: Protocol.Parawing.DestroySessionResponse;
      };
      "Parawing.checkpointSession": {
        paramsType: [Record<string, unknown>?];
        returnType: Record<string, unknown>;
      };
      "Parawing.requestControllerLease": {
        paramsType: [Record<string, unknown>?];
        returnType: Record<string, unknown>;
      };
      "Parawing.approveControllerLease": {
        paramsType: [Record<string, unknown>?];
        returnType: Record<string, unknown>;
      };
      "Parawing.releaseControllerLease": {
        paramsType: [Record<string, unknown>?];
        returnType: Record<string, unknown>;
      };
      "Parawing.revokeControllerLease": {
        paramsType: [Record<string, unknown>?];
        returnType: Record<string, unknown>;
      };
      "Parawing.getControllerLease": {
        paramsType: [Record<string, unknown>?];
        returnType: Record<string, unknown>;
      };
      "Parawing.performSealedFill": {
        paramsType: [Record<string, unknown>];
        returnType: Record<string, unknown>;
      };
      "Parawing.performTokenizedFill": {
        paramsType: [Record<string, unknown>];
        returnType: Record<string, unknown>;
      };
      "Parawing.suspendSession": {
        paramsType: [Record<string, unknown>?];
        returnType: Record<string, unknown>;
      };
      "Parawing.resumeSession": {
        paramsType: [Record<string, unknown>?];
        returnType: Record<string, unknown>;
      };
      "Parawing.roamSession": {
        paramsType: [Record<string, unknown>?];
        returnType: Record<string, unknown>;
      };
      "Parawing.issueAttestedKeyLease": {
        paramsType: [Record<string, unknown>];
        returnType: Record<string, unknown>;
      };
      "Parawing.releaseDbscCredential": {
        paramsType: [Record<string, unknown>];
        returnType: Record<string, unknown>;
      };
      "Parawing.requestActionApproval": {
        paramsType: [Record<string, unknown>];
        returnType: Record<string, unknown>;
      };
      "Parawing.submitApprovalDecision": {
        paramsType: [Record<string, unknown>];
        returnType: Record<string, unknown>;
      };
      "Parawing.startSceneStreamV2": {
        paramsType: [Protocol.Parawing.StartSceneStreamV2Request?];
        returnType: Protocol.Parawing.StartSceneStreamV2Response;
      };
      "Parawing.stopSceneStreamV2": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.StopSceneStreamV2Response;
      };
      "Parawing.recordSceneV2": {
        paramsType: [Protocol.Parawing.RecordSceneV2Request?];
        returnType: Protocol.Parawing.RecordSceneV2Response;
      };
      "Parawing.getHandlerRegions": {
        paramsType: [Protocol.Parawing.TargetScopedRequest?];
        returnType: Protocol.Parawing.GetHandlerRegionsResponse;
      };
      "Parawing.getInputJournalState": {
        paramsType: [Protocol.Parawing.GetInputJournalStateRequest?];
        returnType: Protocol.Parawing.GetInputJournalStateResponse;
      };
    }
  }
}
