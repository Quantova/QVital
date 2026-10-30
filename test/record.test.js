// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function birthRecord(key, subject) {
  return Q.birth({ key, registryNo: 'B 2026 0001', subject: Q.keyId(subject), place: 'City Hospital', bornAt: '2026-01-01T09:30:00.000Z', registrarLabel: 'Civil Registry' });
}

test('a birth is a well formed signed record of the registrar', () => {
  const registrar = freshKey();
  const person = freshKey();
  const b = birthRecord(registrar, person);
  assert.strictEqual(b.format, 'qvital/1');
  assert.strictEqual(b.type, 'birth');
  assert.strictEqual(b.algorithm, 'ML-DSA-65');
  assert.strictEqual(b.signer.id, Q.keyId(registrar));
  assert.strictEqual(b.statement.registrarKeyId, Q.keyId(registrar));
  assert.strictEqual(b.statement.subjectKeyId, Q.keyId(person));
  assert.match(b.statement.vitalId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(b.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the name, marriage and correction records chain to the same record', () => {
  const registrar = freshKey();
  const person = freshKey();
  const partner = freshKey();
  const b = birthRecord(registrar, person);
  const nm = Q.name({ key: registrar, birth: b, changeRef: 'ORDER 2026 55' });
  const mr = Q.marriage({ key: registrar, record: b, partner: Q.keyId(partner), place: 'Town Hall' });
  const co = Q.correction({ key: registrar, record: mr, reason: 'spelling of place' });
  assert.strictEqual(nm.statement.vitalId, b.statement.vitalId);
  assert.strictEqual(nm.statement.birthRef, Q.recordRef(b));
  assert.strictEqual(mr.statement.priorRef, Q.recordRef(b));
  assert.strictEqual(mr.statement.partnerKeyId, Q.keyId(partner));
  assert.strictEqual(co.statement.priorRef, Q.recordRef(mr));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const person = freshKey();
  const base = { key, registryNo: 'B1', subject: Q.keyId(person), place: 'Here', bornAt: '2026-01-01T09:30:00.000Z' };
  assert.throws(() => Q.birth(Object.assign({}, base, { registryNo: '' })), /registryNo is 1 to/);
  assert.throws(() => Q.birth(Object.assign({}, base, { place: '' })), /place cannot be empty/);
  assert.throws(() => Q.birth(Object.assign({}, base, { bornAt: 'yesterday' })), /bornAt must be an ISO/);
  assert.throws(() => Q.birth(Object.assign({}, base, { subject: 'nothex' })), /subject is a/);
  assert.throws(() => Q.birth(Object.assign({}, base, { unknownField: 1 })), /is not an option of birth/);
  const b = birthRecord(key, person);
  assert.throws(() => Q.marriage({ key, record: b, partner: 'nothex', place: 'X' }), /partner is a/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  const person = freshKey();
  assert.throws(() => birthRecord(new Uint8Array(16), person), /32 byte Uint8Array seed/);
  assert.throws(() => birthRecord(new Uint8Array(32), person), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const registrar = freshKey();
  const person = freshKey();
  const b = birthRecord(registrar, person);
  const ok = await Q.verify(b, { type: 'birth', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'birth');
  assert.strictEqual(ok.vitalId, b.statement.vitalId);
  const wrongType = await Q.verify(b, { type: 'death', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(b, { type: 'birth', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const registrar = freshKey();
  const person = freshKey();
  const b = birthRecord(registrar, person);
  const forged = JSON.parse(JSON.stringify(b));
  forged.statement.place = 'Another City';
  const r = await Q.verify(forged, { type: 'birth', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a name change to the birth it refers to', async () => {
  const registrar = freshKey();
  const person = freshKey();
  const b = birthRecord(registrar, person);
  const nm = Q.name({ key: registrar, birth: b, changeRef: 'ORDER 2026 55' });
  const good = await Q.verify(nm, { type: 'name', network: 'testnet', requireAnchor: false, strict: false, prior: b });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherB = birthRecord(registrar, person);
  const bad = await Q.verify(nm, { type: 'name', network: 'testnet', requireAnchor: false, strict: false, prior: otherB });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'B 2026 0001');
  const b = Q.subjectRef(secret, 'B 2026 0001');
  const c = Q.subjectRef(secret, 'B 2026 0002');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the civil registry line', () => {
  assert.strictEqual(Q.KIND, 1509);
  assert.strictEqual(Q.FORMAT, 'qvital/1');
  assert.deepStrictEqual([...Q.TYPES], ['birth', 'name', 'marriage', 'correction', 'death']);
});
