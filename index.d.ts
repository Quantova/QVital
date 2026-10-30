// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type RecordType = 'birth' | 'name' | 'marriage' | 'correction' | 'death';

export interface KeyDescription {
  format: 'qvital-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qvital/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface BirthOptions {
  key: Uint8Array;
  registryNo: string;
  subject: Party;
  place: string;
  bornAt: string;
  registrarLabel?: string;
  registeredAt?: string;
  note?: string;
}

export interface NameOptions {
  key: Uint8Array;
  birth: Envelope;
  changeRef: string;
  registrarLabel?: string;
  changedAt?: string;
  note?: string;
}

export interface MarriageOptions {
  key: Uint8Array;
  record: Envelope;
  partner: Party;
  place: string;
  registrarLabel?: string;
  marriedAt?: string;
  note?: string;
}

export interface CorrectionOptions {
  key: Uint8Array;
  record: Envelope;
  reason: string;
  registrarLabel?: string;
  correctedAt?: string;
  note?: string;
}

export interface DeathOptions {
  key: Uint8Array;
  record: Envelope;
  place: string;
  diedAt: string;
  registrarLabel?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  vitalId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  vitalId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, reference: string): string;
export function birth(options: BirthOptions): Envelope;
export function name(options: NameOptions): Envelope;
export function marriage(options: MarriageOptions): Envelope;
export function correction(options: CorrectionOptions): Envelope;
export function death(options: DeathOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qvital/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1509;
export const TYPES: readonly RecordType[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
