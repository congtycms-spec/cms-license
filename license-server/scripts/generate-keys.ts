import { Ed25519Service } from '../src/crypto/ed25519.service';

const keys = Ed25519Service.generateRawKeyPair();

console.log('==============================================================');
console.log('🔐 ED25519 ASYMMETRIC KEYPAIR GENERATED (RFC 8032 / Libsodium)');
console.log('==============================================================');
console.log(`Key ID (Fingerprint):        ${keys.keyId}`);
console.log(`PUBLIC KEY (32B Base64):     ${keys.publicKeyBase64}`);
console.log(`PRIVATE SEED (32B Base64):   ${keys.privateSeedBase64}`);
console.log('--------------------------------------------------------------');
console.log('1. Copy ED25519_PRIVATE_KEY_BASE64 and ED25519_PUBLIC_KEY_BASE64 into license-server/.env');
console.log('2. Copy ONLY PUBLIC KEY into the WordPress Plugin constant CLPS_ED25519_PUBLIC_KEY');
console.log('3. NEVER expose PRIVATE SEED outside the Central License Server!');
console.log('==============================================================');

