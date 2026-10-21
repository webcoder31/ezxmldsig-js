/*
 * Copyright © 2026 - Thierry Thiers <webcoder31@gmail.com>
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software. You can use, modify
 * and/or redistribute the software under the terms of the CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * http://www.cecill.info
 */

import { constants, createCipheriv, createDecipheriv, privateDecrypt, publicEncrypt, randomBytes, type KeyObject } from 'node:crypto';

import * as alg from './algorithms.js';

/**
 * The encryption of the token data, as xmlseclibs performs it for the PHP
 * library: a session key per token, the data encrypted with it, the
 * initialization vector written before the encrypted data and, for AES-GCM,
 * the authentication tag after them; the session key encrypted for the
 * recipient with RSA-OAEP (MGF1 with SHA-1, no label).
 */

interface Cipher {
  /** The OpenSSL name of the cipher. */
  readonly name: string;
  readonly keySize: number;
  readonly blockSize: number;
  readonly ivSize: number;
  readonly gcm: boolean;
}

/** The length of the authentication tag of AES-GCM. */
const AUTH_TAG_LENGTH = 16;

const CIPHERS: Readonly<Record<string, Cipher>> = {
  [alg.TRIPLEDES_CBC]: { name: 'des-ede3-cbc', keySize: 24, blockSize: 8, ivSize: 8, gcm: false },
  [alg.AES128_CBC]: { name: 'aes-128-cbc', keySize: 16, blockSize: 16, ivSize: 16, gcm: false },
  [alg.AES192_CBC]: { name: 'aes-192-cbc', keySize: 24, blockSize: 16, ivSize: 16, gcm: false },
  [alg.AES256_CBC]: { name: 'aes-256-cbc', keySize: 32, blockSize: 16, ivSize: 16, gcm: false },
  [alg.AES128_GCM]: { name: 'aes-128-gcm', keySize: 16, blockSize: 16, ivSize: 12, gcm: true },
  [alg.AES192_GCM]: { name: 'aes-192-gcm', keySize: 24, blockSize: 16, ivSize: 12, gcm: true },
  [alg.AES256_GCM]: { name: 'aes-256-gcm', keySize: 32, blockSize: 16, ivSize: 12, gcm: true },
};

function cipherOf(algorithm: string): Cipher {
  const cipher = CIPHERS[algorithm];
  if (cipher === undefined) {
    throw new Error(`Unknown symmetric algorithm: ${algorithm}`);
  }
  return cipher;
}

/**
 * Generates a session key for a symmetric algorithm. A Triple DES key gets
 * the parity bits xmlseclibs sets.
 */
export function generateSessionKey(algorithm: string): Buffer {
  const key = randomBytes(cipherOf(algorithm).keySize);
  if (algorithm === alg.TRIPLEDES_CBC) {
    for (let i = 0; i < key.length; i++) {
      let byte = (key[i] as number) & 0xfe;
      let parity = 1;
      for (let j = 1; j < 8; j++) {
        parity ^= (byte >> j) & 1;
      }
      byte |= parity;
      key[i] = byte;
    }
  }
  return key;
}

/**
 * Encrypts data with a session key: the initialization vector, the
 * encrypted data and, for AES-GCM, the authentication tag. CBC data are
 * padded as xmlseclibs pads them (each padding byte is the padding length).
 */
export function encryptSymmetric(algorithm: string, key: Buffer, data: Buffer): Buffer {
  const cipher = cipherOf(algorithm);
  const iv = randomBytes(cipher.ivSize);
  if (cipher.gcm) {
    const encryptor = createCipheriv(cipher.name as 'aes-256-gcm', key, iv, { authTagLength: AUTH_TAG_LENGTH });
    const encrypted = Buffer.concat([encryptor.update(data), encryptor.final()]);
    return Buffer.concat([iv, encrypted, encryptor.getAuthTag()]);
  }
  const padding = cipher.blockSize - (data.length % cipher.blockSize);
  const encryptor = createCipheriv(cipher.name, key, iv);
  encryptor.setAutoPadding(false);
  return Buffer.concat([iv, encryptor.update(Buffer.concat([data, Buffer.alloc(padding, padding)])), encryptor.final()]);
}

/**
 * Decrypts data encrypted by `encryptSymmetric()`, as xmlseclibs does: a
 * session key longer than the key of the algorithm is truncated (as PHP's
 * openssl_decrypt() does), a shorter one is refused, and the CBC padding is
 * removed by its last byte, without checking it. Every failure throws: the
 * caller gives the same error for all of them.
 */
export function decryptSymmetric(algorithm: string, sessionKey: Buffer, data: Buffer): Buffer {
  const cipher = cipherOf(algorithm);
  if (sessionKey.length < cipher.keySize) {
    throw new Error('Session key too short.');
  }
  const key = sessionKey.subarray(0, cipher.keySize);
  const iv = data.subarray(0, cipher.ivSize);
  const encrypted = data.subarray(cipher.ivSize);
  if (iv.length !== cipher.ivSize) {
    throw new Error('Truncated data.');
  }
  if (cipher.gcm) {
    if (encrypted.length < AUTH_TAG_LENGTH) {
      throw new Error('Authentication tag length is invalid.');
    }
    const decryptor = createDecipheriv(cipher.name as 'aes-256-gcm', key, iv, { authTagLength: AUTH_TAG_LENGTH });
    decryptor.setAuthTag(encrypted.subarray(encrypted.length - AUTH_TAG_LENGTH));
    return Buffer.concat([decryptor.update(encrypted.subarray(0, encrypted.length - AUTH_TAG_LENGTH)), decryptor.final()]);
  }
  const decryptor = createDecipheriv(cipher.name, key, iv);
  decryptor.setAutoPadding(false);
  const decrypted = Buffer.concat([decryptor.update(encrypted), decryptor.final()]);
  // PHP: substr($data, 0, -$padLen), which gives an empty string for a
  // padding length of 0 or longer than the data.
  const padding = decrypted.length === 0 ? 0 : decrypted[decrypted.length - 1] as number;
  return padding === 0 || padding > decrypted.length ? Buffer.alloc(0) : decrypted.subarray(0, decrypted.length - padding);
}

/** Encrypts a session key for the recipient with RSA-OAEP (MGF1-SHA1). */
export function encryptKey(publicKey: KeyObject, sessionKey: Buffer): Buffer {
  return publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, sessionKey);
}

/** Decrypts a session key with the private key of the recipient
(RSA-OAEP, MGF1-SHA1). */
export function decryptKey(privateKey: KeyObject, encryptedKey: Buffer): Buffer {
  return privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, encryptedKey);
}
