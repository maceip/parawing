// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Stores generation-local CDP object handles and compiled-script entries.

const __handles = new Map<string, unknown>();
const __objectGroups = new Map<string, Set<string>>();
const __handleGroups = new Map<string, string>();
let __handleSeq = 0;

// Stamped into every handle and compiled-script id so the engine can route an id back to the
// isolate that minted it. Isolates start with independent sequences, so bare `ps:N` collides.
// Global scope cannot generate random values, so the engine sets this when the session opens.
let __isolateStamp = "";

export function setIsolateStamp(stamp: unknown): void {
  if (typeof stamp === "string" && stamp) __isolateStamp = stamp;
}

function stampedId(prefix: string, seq: number): string {
  return __isolateStamp ? `${prefix}:${__isolateStamp}:${seq}` : `${prefix}:${seq}`;
}

export function mintHandle(value: unknown, objectGroup?: string): string {
  const id = stampedId("ps", ++__handleSeq);
  __handles.set(id, value);
  if (typeof objectGroup === "string" && objectGroup.length > 0) {
    let groupSet = __objectGroups.get(objectGroup);
    if (!groupSet) {
      groupSet = new Set<string>();
      __objectGroups.set(objectGroup, groupSet);
    }
    groupSet.add(id);
    __handleGroups.set(id, objectGroup);
  }
  return id;
}

export function lookupHandle(id: unknown): unknown {
  if (typeof id !== "string") return undefined;
  return __handles.get(id);
}

export function releaseHandle(id: unknown): void {
  if (typeof id !== "string") return;
  __handles.delete(id);
  const group = __handleGroups.get(id);
  if (group !== undefined) {
    __handleGroups.delete(id);
    const groupSet = __objectGroups.get(group);
    if (groupSet) {
      groupSet.delete(id);
      if (groupSet.size === 0) __objectGroups.delete(group);
    }
  }
}

export function releaseObjectGroup(group: unknown): number {
  if (typeof group !== "string" || group.length === 0) return 0;
  const groupSet = __objectGroups.get(group);
  if (!groupSet) return 0;
  let released = 0;
  for (const id of groupSet) {
    if (__handles.delete(id)) released++;
    __handleGroups.delete(id);
  }
  __objectGroups.delete(group);
  return released;
}

export interface CompiledScript {
  source: string;
  sourceURL: string;
}

const __compiledScripts = new Map<string, CompiledScript>();
let __compiledScriptSeq = 0;

export function compileScriptEntry(source: string, sourceURL: string): string {
  const scriptId = stampedId("cs", ++__compiledScriptSeq);
  __compiledScripts.set(scriptId, { source, sourceURL });
  return scriptId;
}

export function getCompiledScript(scriptId: unknown): CompiledScript | undefined {
  if (typeof scriptId !== "string") return undefined;
  return __compiledScripts.get(scriptId);
}
