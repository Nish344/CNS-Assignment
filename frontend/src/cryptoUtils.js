// cryptoUtils.js
// Utility wrappers for Web Crypto API

// Helper to convert string to ArrayBuffer
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

// Helper to convert ArrayBuffer to string
function ab2str(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return binary;
}

function ab2b64(buf) {
  return btoa(ab2str(buf));
}

function b642ab(b64) {
  return str2ab(atob(b64));
}

// Generate Key Pairs (we need two: one for wrapping RSA-OAEP, one for signing RSA-PSS)
export async function generateKeyPairs() {
  const encKeyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const signKeyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

  // Export to JWK
  const pubEncJwk = await window.crypto.subtle.exportKey("jwk", encKeyPair.publicKey);
  const privEncJwk = await window.crypto.subtle.exportKey("jwk", encKeyPair.privateKey);
  const pubSignJwk = await window.crypto.subtle.exportKey("jwk", signKeyPair.publicKey);
  const privSignJwk = await window.crypto.subtle.exportKey("jwk", signKeyPair.privateKey);

  const publicKeyPayload = JSON.stringify({ enc: pubEncJwk, sign: pubSignJwk });
  const privateKeyPayload = JSON.stringify({ enc: privEncJwk, sign: privSignJwk });

  return { publicKey: publicKeyPayload, privateKey: privateKeyPayload };
}

export async function wrapKey(rawAesKeyBuffer, publicKeyString) {
  const keys = JSON.parse(publicKeyString);
  const pubEncKey = await window.crypto.subtle.importKey(
    "jwk",
    keys.enc,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
  
  const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    pubEncKey,
    rawAesKeyBuffer
  );
  
  return ab2b64(encryptedKeyBuffer);
}

export async function unwrapKey(wrappedKeyB64, privateKeyString) {
  const keys = JSON.parse(privateKeyString);
  const privEncKey = await window.crypto.subtle.importKey(
    "jwk",
    keys.enc,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );

  const encryptedKeyBuffer = b642ab(wrappedKeyB64);
  const rawAesKeyBuffer = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privEncKey,
    encryptedKeyBuffer
  );

  return rawAesKeyBuffer;
}

export async function signData(dataBuffer, privateKeyString) {
  const keys = JSON.parse(privateKeyString);
  const privSignKey = await window.crypto.subtle.importKey(
    "jwk",
    keys.sign,
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signatureBuffer = await window.crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    privSignKey,
    dataBuffer
  );

  return ab2b64(signatureBuffer);
}

export async function verifySignature(dataBuffer, signatureB64, publicKeyString) {
  const keys = JSON.parse(publicKeyString);
  const pubSignKey = await window.crypto.subtle.importKey(
    "jwk",
    keys.sign,
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signatureBuffer = b642ab(signatureB64);
  const isValid = await window.crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 },
    pubSignKey,
    signatureBuffer,
    dataBuffer
  );

  return isValid;
}

// Generates AES-GCM key and encrypts data. Returns cipher+tag, nonce, and the raw AES key buffer.
export async function encryptDataAESGCM(dataBuffer) {
  const rawAesKey = window.crypto.getRandomValues(new Uint8Array(32)); // 256 bit
  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    rawAesKey,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  
  // In WebCrypto, GCM appends the auth tag to the end of the ciphertext.
  const cipherAndTagBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    aesKey,
    dataBuffer
  );

  // We'll extract tag and ciphertext separately to match our python backend expectations, 
  // though Python expects them separate. Actually, our new python server just stores them 
  // as strings blindly, so we can just base64 them as is.
  // Wait, let's just base64 the combined cipher+tag since WebCrypto does it together.
  // We'll mock the 'tag' as empty string so it fits the DB schema.
  
  return {
    encryptedDataB64: ab2b64(cipherAndTagBuffer),
    nonceB64: ab2b64(nonce),
    tagB64: "", // Not needed for WebCrypto since it's appended, but keeping for schema
    rawAesKeyBuffer: rawAesKey.buffer
  };
}

export async function decryptDataAESGCM(encryptedDataB64, nonceB64, rawAesKeyBuffer) {
  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    rawAesKeyBuffer,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const nonce = b642ab(nonceB64);
  const cipherAndTagBuffer = b642ab(encryptedDataB64);

  try {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      aesKey,
      cipherAndTagBuffer
    );
    return decryptedBuffer;
  } catch (e) {
    console.error("Decryption or MAC verification failed", e);
    return null;
  }
}
