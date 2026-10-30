# QVital

QVital is a live production post quantum civil registry record tool for registrars on the Quantova network. It proves the birth, name change, marriage, correction and death entries of a civil record, and it lets any third party confirm that history without trusting the party that created it.

QVital proves records without disclosing them. Names and the detail of a person's civil record stay private on the systems of the registry that holds them. Only a salted cryptographic commitment is written to the chain, and no personal detail is ever published. A person is named only by a chain address.

## What it records

Each record is a signed envelope of one of five types.

1. birth, a registrar states the registry number, person, place of birth and time of birth.
2. name, a registrar records a name change by its order reference.
3. marriage, a registrar records a marriage and names the partner by key.
4. correction, a registrar records a correction to the record and states why.
5. death, a registrar records the place and time of death.

Every record is signed with ML-DSA-65 under FIPS 204 by the registrar, and each later record links to the one before it so the whole civil record forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qvital
```

## Use

```js
const qvital = require('@quantovainc/qvital');

const registrar = qvital.generateKey();
const person = qvital.generateKey();
const record = qvital.birth({
  key: registrar,
  registryNo: 'B 2026 0001',
  subject: qvital.keyId(person),
  place: 'City Hospital',
  bornAt: '2026-01-01T09:30:00.000Z',
  registrarLabel: 'Civil Registry',
});

const anchored = await qvital.anchor(record, { seed, index: 0, network: 'testnet' });
const result = await qvital.verify(anchored[0], { type: 'birth', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural person. The person and the registrar are chain addresses, and linking an address to a person is a separate attestation held off the chain.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
