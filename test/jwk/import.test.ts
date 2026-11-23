import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CompactEncrypt,
  exportJWK,
  exportPKCS8,
  exportSPKI,
  generateKeyPair,
  importJWK,
  importPKCS8,
  importSPKI,
  compactDecrypt,
} from '../../src/index.js'
import { errorLike } from '../_errors.js'

test('PEM imports reject symmetric algorithms', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
  const spki = await exportSPKI(publicKey)
  const pkcs8 = await exportPKCS8(privateKey)
  const expected = {
    code: 'ERR_JOSE_NOT_SUPPORTED',
    message: 'Invalid or unsupported "alg" (Algorithm) value',
  }

  for (const alg of ['HS256', 'A128KW']) {
    await assert.rejects(importSPKI(spki, alg), errorLike(expected))
    await assert.rejects(importPKCS8(pkcs8, alg), errorLike(expected))
  }
})

test('private key import extractable option must be a boolean', async () => {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true })
  const pkcs8 = await exportPKCS8(privateKey)
  const jwk = await exportJWK(privateKey)

  await assert.rejects(importPKCS8(pkcs8, 'ES256', { extractable: 'false' as never }), TypeError)
  await assert.rejects(importJWK(jwk, 'ES256', { extractable: 'false' as never }), TypeError)
})

test('key imports snapshot the extractable option', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
  const pkcs8 = await exportPKCS8(privateKey)
  const jwk = await exportJWK(publicKey)

  for (const importKey of [
    (options) => importPKCS8(pkcs8, 'ES256', options),
    (options) => importJWK(jwk, 'ES256', options),
  ]) {
    let reads = 0
    const key = await importKey({
      get extractable() {
        return reads++ === 0 ? false : true
      },
    })

    assert.strictEqual(reads, 1)
    assert.strictEqual(key.extractable, false)
  }
})

// Only two generated key pairs back every case below: one ES256 pair and one ECDH-ES pair.
const es256 = await generateKeyPair('ES256', { extractable: true })
const ecdh = await generateKeyPair('ECDH-ES', { extractable: true })
const es256Private = await exportJWK(es256.privateKey)
const es256Public = await exportJWK(es256.publicKey)
const ecdhPrivate = await exportJWK(ecdh.privateKey)
const ecdhPublic = await exportJWK(ecdh.publicKey)

test('importJWK enforces the declared "use" constraint', async () => {
  await assert.doesNotReject(importJWK({ ...es256Public, use: 'sig' }, 'ES256'))
  await assert.rejects(
    importJWK({ ...es256Public, use: 'enc' }, 'ES256'),
    errorLike({
      name: 'TypeError',
      message: 'Invalid key for this operation, its "use" must be "sig" when present',
    }),
  )
  await assert.doesNotReject(importJWK({ ...ecdhPublic, use: 'enc' }, 'ECDH-ES'))
  await assert.rejects(
    importJWK({ ...ecdhPublic, use: 'sig' }, 'ECDH-ES'),
    errorLike({
      name: 'TypeError',
      message: 'Invalid key for this operation, its "use" must be "enc" when present',
    }),
  )
})

test('importJWK enforces the declared "key_ops" constraint', async () => {
  await assert.doesNotReject(importJWK({ ...es256Public, key_ops: ['verify'] }, 'ES256'))
  await assert.doesNotReject(importJWK({ ...es256Private, key_ops: ['sign'] }, 'ES256'))
  await assert.rejects(
    importJWK({ ...es256Public, key_ops: ['sign'] }, 'ES256'),
    errorLike({
      name: 'TypeError',
      message: 'Invalid key for this operation, its "key_ops" must include "verify" when present',
    }),
  )
  await assert.rejects(
    importJWK({ ...es256Private, key_ops: ['verify'] }, 'ES256'),
    errorLike({
      name: 'TypeError',
      message: 'Invalid key for this operation, its "key_ops" must include "sign" when present',
    }),
  )
  await assert.doesNotReject(importJWK({ ...ecdhPrivate, key_ops: ['deriveBits'] }, 'ECDH-ES'))
  await assert.rejects(
    importJWK({ ...ecdhPrivate, key_ops: ['sign'] }, 'ECDH-ES'),
    errorLike({
      name: 'TypeError',
      message:
        'Invalid key for this operation, its "key_ops" must include "deriveBits" when present',
    }),
  )
})

test('importJWK enforces the declared "alg" constraint', async () => {
  await assert.doesNotReject(importJWK({ ...es256Public, alg: 'ES256' }))
  await assert.rejects(
    importJWK({ ...es256Public, alg: 'ES384' }, 'ES256'),
    errorLike({
      name: 'TypeError',
      message: 'Invalid key for this operation, its "alg" must be "ES256" when present',
    }),
  )
})

test('importJWK without declared constraints stays permissive across an export round trip', async () => {
  // exportJWK intentionally strips use/key_ops/ext/alg metadata, so an exported and
  // re-imported key carries no constraints and must remain usable.
  const reimportedPublic = await importJWK(es256Public, 'ES256', { extractable: true })
  const reimportedPrivate = await importJWK(es256Private, 'ES256', { extractable: true })
  assert.deepStrictEqual(await exportJWK(reimportedPublic), es256Public)
  assert.deepStrictEqual(await exportJWK(reimportedPrivate), es256Private)

  const jwe = await new CompactEncrypt(new TextEncoder().encode('round trip'))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })
    .encrypt(await importJWK(ecdhPublic, 'ECDH-ES'))
  const { plaintext } = await compactDecrypt(jwe, await importJWK(ecdhPrivate, 'ECDH-ES'))
  assert.deepStrictEqual(plaintext, new TextEncoder().encode('round trip'))
})
