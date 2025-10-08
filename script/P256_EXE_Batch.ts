// src/p256Data.ts
import { p256 } from "@noble/curves/p256";
import type { Hex } from "viem";
import { fromHex } from 'viem';
import { writeFileSync } from 'fs';
import { WebCryptoP256 } from "ox";

/** P-256 curve order (𝑛) */
const P256_N = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);

/* ────────────────────────────────────────────── helper: normalize ── */
function normalizeP256Signature(
  r: Hex,
  s: Hex
): { r: Hex; s: Hex } {
  const sBig = BigInt(s);
  const halfN = P256_N / 2n;

  if (sBig > halfN) {
    const sNormalized = P256_N - sBig;
    const sHex = `0x${sNormalized.toString(16).padStart(64, "0")}` as Hex;
    return { r, s: sHex };
  }
  return { r, s };
}

/* ────────────────────────────────────────────── helper: hex utils ── */
const toHex = (bytes: Uint8Array): Hex =>
  `0x${Buffer.from(bytes).toString("hex")}` as Hex;

const toHex32 = (n: bigint): Hex =>
  `0x${n.toString(16).padStart(64, "0")}` as Hex;

const bigintToHex = (n: bigint): Hex => toHex32(n);

/* ──────────────────────────────────────────────────────────── main ── */
export const p256Data = (async () => {
  const privKey = p256.utils.randomPrivateKey();
  const pubKey = p256.getPublicKey(privKey, false);

  const P256_xHex = toHex(pubKey.slice(1, 33));
  const P256_yHex = toHex(pubKey.slice(33));

  const challengeBytesHex = '0x972c09a5a229ddc18ba10c5f19f4ed47156c00a319966201e4ce93a8eec9a05f';
  const challengeBytes = fromHex(challengeBytesHex, 'bytes');
  const P256_hashHex = toHex(challengeBytes);

  const signature = p256.sign(challengeBytes, privKey);
  const rHex = bigintToHex(signature.r);
  const sHex = bigintToHex(signature.s);

  const { r: P256_lowSR, s: P256_lowSS } = normalizeP256Signature(rHex, sHex);

  const isValidSignature = p256.verify(signature, challengeBytes, pubKey);
  console.log("✅ signature verified:", isValidSignature);

  const result = {
    P256_hashHex,
    P256_lowSR,
    P256_lowSS,
    P256_xHex,
    P256_yHex,
    challenge: P256_hashHex,
    rBigInt: signature.r.toString(),
    sBigInt: signature.s.toString(),
    recovery: signature.recovery,
    isValidSignature,
  };
  
  // Print to console (with full object, including BigInts)
  console.log("📦 on-chain payload:", {
    ...result,
    webauthnData: signature, // for debugging only
  });
  
    /* 1️⃣  KEY PAIR --------------------------------------------------- */
    const keyPair = await WebCryptoP256.createKeyPair();
    console.log("Key pair generated:", keyPair);
  
    const publicKey = keyPair.publicKey;
    console.log("Public key:", publicKey);
  
    const privateKey = keyPair.privateKey;
    console.log("Private key:", privateKey);

    /* 3️⃣  SIGN -------------------------------------------------------- */
    const { r, s } = await WebCryptoP256.sign({
      privateKey: privateKey,
      payload: P256_hashHex,
    });

    console.log("Signature components - r:", r, "s:", s);

    const P256NONKEY_rHex = bigintToHex(r);
    const P256NONKEY_sHex = bigintToHex(s);

    console.log("r as hex:", P256NONKEY_rHex);
    console.log("s as hex:", P256NONKEY_sHex);

    /* 4️⃣  VERIFY (sanity-check) -------------------------------------- */
    const isValid = await WebCryptoP256.verify({
      publicKey: publicKey,
      payload: P256_hashHex,
      signature: { r, s }
    });
  
    console.log("Signature verification result:", isValid);
    
    if (isValid) {
      console.log("✅ Signature is VALID!");
    } else {
      console.log("❌ Signature is INVALID!");
    }
  
    /* 6️⃣  RETURN + LOG ----------------------------------------------- */
    const result2 = {
      P256NONKEY_hashHex: P256_hashHex,
      P256NONKEY_rHex,
      P256NONKEY_sHex,
      P256NONKEY_xHex: toHex32(keyPair.publicKey.x),
      P256NONKEY_yHex: toHex32(keyPair.publicKey.y),
      challenge: P256_hashHex, // alias to emphasise "challenge" terminology
      // Convert BigInts to strings for JSON serialization
      webauthnData: { 
        r: r.toString(), 
        s: s.toString() 
      },
      isValidSignature: isValid,
    };
  
    console.log("📦 on-chain payload:", result2);
 
    
    
    // ✅ Write only serializable parts to JSON
    // Create a JSON-safe version by converting all BigInts to strings
    const jsonSafeResult = {
      ...result,
      // webauthnData is already removed from result, so we're good
    };
    
    const jsonSafeResult2 = {
      ...result2,
      // webauthnData now contains strings instead of BigInts
    };
    
    writeFileSync(
      "test/data/p256_exe_batch.json",
      JSON.stringify({result: jsonSafeResult, result2: jsonSafeResult2}, null, 2)
    );
    
  return { result, result2 };
})();