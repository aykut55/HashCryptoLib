#ifndef CRYPTOAPI_PROVIDERS_ALGORITHM_CAPABILITY_MATRIX_H
#define CRYPTOAPI_PROVIDERS_ALGORITHM_CAPABILITY_MATRIX_H

// cryptopp890
// 
// Reference only -- no declarations, nothing here is included by any .cpp.
//
// Central encryption/decryption capability matrix across all four provider libraries: Windows
// CNG/BCrypt ("MS"), Crypto++ 8.9.0 ("CPP"), Botan 3.13.0 ("Botan"), OpenSSL 4.0.2 ("OSSL").
// Scope is deliberately encryption/decryption only (AEAD, legacy block modes, raw ciphers, RSA
// encryption) -- hashes, MACs, digital signatures and key-agreement schemes are a separate,
// later phase and are NOT listed here.
//
// Legend:
//   W  = Wired AND verified by an actual test in this repository (see CryptoApiTester.cpp /
//        the *_provider_smoketest.cpp files run during development).
//   Y  = The underlying library supports this algorithm per its own documentation/headers, but it
//        is NOT wired into this SDK's provider classes yet.
//   N  = The underlying library does not support this algorithm at all.
//   Y* / N* = Same as Y/N, but lower confidence (based on general library knowledge, not
//        independently re-checked against 3rdParty/<lib>'s exact headers for this repo's exact
//        version) -- re-verify against the vendored source before relying on it for real work.
//
// Only "W" cells are hard facts this repository has proven true by compiling and running code.
// Everything else is a planning aid, not a guarantee.

// ================================================================================================
// AEAD (authenticated encryption) -- see AeadAlgorithm in ProviderTypes.h for the ones we track
// ================================================================================================
//
//   Algorithm                    MS    CPP   Botan   OSSL
//   ------------------------     ----  ----  -----   ----
//   AES-128-GCM                  W     W     W       W
//   AES-192-GCM                  W     W     W       W
//   AES-256-GCM                  W     W     W       W
//   AES-128-CCM                  W     W     W       W
//   AES-192-CCM                  W     W     W       W
//   AES-256-CCM                  W     W     W       W
//   AES-128-EAX                  N     W     W       N
//   AES-192-EAX                  N     W     W       N
//   AES-256-EAX                  N     W     W       N
//   AES-128-SIV                  N     N     W       W
//   AES-256-SIV                  N     N     W       W
//   AES-128-GCM-SIV              N     N     W       N
//   AES-256-GCM-SIV              N     N     W       N
//   ChaCha20-Poly1305            N     W     W       W
//   Twofish-GCM                  N     W     W       N
//   Serpent-GCM                  N     W     W       N
//   Camellia-GCM                 N     W     W       N*
//   ---- not in our AeadAlgorithm enum yet, but exist in these libraries: ----
//   XChaCha20-Poly1305           N     Y     N*      N
//   AES-OCB                      N     N*    Y       Y
//
// ================================================================================================
// Legacy (non-authenticated) block cipher modes -- see LegacySymmetricAlgorithm in
// ProviderTypes.h. All rows below assume AES as the block cipher unless noted otherwise.
// ================================================================================================
//
//   Mode (AES)                   MS    CPP   Botan   OSSL
//   ------------------------     ----  ----  -----   ----
//   CBC                          W     W     W       W
//   CTR                          N     W     W       W
//   CFB                          W     W     W       W
//   OFB                          N     W     W       W
//   ECB                          W     W     N       W
//   ---- not in our LegacySymmetricAlgorithm enum yet: ----
//   XTS                          Y*    Y*    Y*      Y
//   CTS (ciphertext stealing)    N     Y*    N*      N*
//
// ================================================================================================
// Legacy block ciphers as standalone engines (usable with CBC/ECB/CFB generically in the owning
// library, independent of AES). RC2/DES/3DES/RC4 are already in LegacySymmetricAlgorithm and wired
// for Microsoft only; the rest are not in our enum at all yet.
// ================================================================================================
//
//   Cipher                       MS    CPP   Botan   OSSL
//   ------------------------     ----  ----  -----   ----
//   DES                          W     Y     Y       Y
//   Triple-DES (3DES/EDE3)       W     Y     Y       Y
//   RC2                          W     Y     N*      Y
//   RC4 (stream, see below too)  W     Y     Y       Y
//   ---- not in our enum: ----
//   Blowfish                     N     Y     Y       Y
//   CAST-128                     N     Y     Y       Y
//   CAST-256                     N     Y     N*      N
//   IDEA                         N     Y     Y       Y*
//   Camellia (as plain cipher)   N     Y     Y       Y
//   Serpent (as plain cipher)    N     Y     Y       N
//   Twofish (as plain cipher)    N     Y     Y       N
//   MARS                         N     Y     N       N
//   RC6                          N     Y     N       N
//   SM4                          N     Y     Y       Y
//   ARIA                         N     Y     Y       Y
//   GOST 28147-89                N     Y     Y       Y*
//
// ================================================================================================
// Raw stream ciphers (not AEAD-wrapped)
// ================================================================================================
//
//   Cipher                       MS    CPP   Botan   OSSL
//   ------------------------     ----  ----  -----   ----
//   RC4 / ARC4                   W     Y     Y       Y
//   ChaCha20 (raw)               N     Y     Y       Y
//   XChaCha20                    N     Y     N       N
//   Salsa20                      N     Y     Y       N
//   XSalsa20                     N     Y     N       N
//
// ================================================================================================
// Asymmetric encryption -- see AsymmetricAlgorithm in ProviderTypes.h (RSA only, so far)
// ================================================================================================
//
//   Algorithm                    MS    CPP   Botan   OSSL
//   ------------------------     ----  ----  -----   ----
//   RSA (encrypt/decrypt)        W     Y     Y       Y
//
// ================================================================================================
// CRYPTO++ 8.9.0 -- full algorithm surface (not limited to encryption/decryption). Some entries
// necessarily repeat what the encryption/decryption tables above already say -- that's expected,
// this section catalogues the whole library, not just what this SDK wires. Source:
// https://github.com/weidai11/cryptopp (README, as of 2023-10-01); confirmed present as headers
// in the vendored copy at 3rdParty/cryptopp890/*.h.
// ================================================================================================
//
//   Authenticated encryption schemes:
//       GCM, CCM, EAX, ChaCha20Poly1305, XChaCha20Poly1305
//
//   High-speed stream ciphers:
//       ChaCha (8/12/20), ChaCha (IETF), Panama, Salsa20, Sosemanuk, XSalsa20, XChaCha20
//
//   AES and AES candidates:
//       AES (Rijndael), RC6, MARS, Twofish, Serpent, CAST-256
//
//   Other block ciphers:
//       ARIA, Blowfish, Camellia, CHAM, HIGHT, IDEA, Kalyna (128/256/512), LEA, SEED, RC5,
//       SHACAL-2, SIMON (64/128), Skipjack, SPECK (64/128), Simeck, SM4,
//       Threefish (256/512/1024), Triple-DES (DES-EDE2 and DES-EDE3), TEA, XTEA
//
//   Block cipher modes of operation:
//       ECB, CBC, CBC ciphertext stealing (CTS), CFB, OFB, counter mode (CTR), XTS
//
//   Message authentication codes:
//       BLAKE2s, BLAKE2b, CMAC, CBC-MAC, DMAC, GMAC, HMAC, Poly1305, Poly1305 (IETF),
//       SipHash, Two-Track-MAC, VMAC
//
//   Hash functions:
//       BLAKE2s, BLAKE2b, Keccak (F1600), LSH (256/512), SHA-1, SHA-2 (224/256/384/512),
//       SHA-3 (224/256), SHA-3 (384/512), SHAKE (128/256), SipHash, SM3, Tiger,
//       RIPEMD (128/160/256/320), Whirlpool
//
//   Public-key cryptography:
//       RSA, DSA, Deterministic DSA, ElGamal, Nyberg-Rueppel (NR), Rabin-Williams (RW), LUC,
//       LUCELG, EC-based German Digital Signature (ECGDSA), DLIES (variants of DHAES), ESIGN
//
//   Padding schemes for public-key systems:
//       PKCS#1 v2.0, OAEP, PSS, PSSR, IEEE P1363 EMSA2 and EMSA5
//
//   Key agreement schemes:
//       Diffie-Hellman (DH), Unified Diffie-Hellman (DH2), Menezes-Qu-Vanstone (MQV),
//       Hashed MQV (HMQV), Fully Hashed MQV (FHMQV), LUCDIF, XTR-DH
//
//   Elliptic curve cryptography:
//       ECDSA, Deterministic ECDSA, ed25519, ECNR, ECIES, ECDH, ECMQV, x25519
//
//   Insecure or obsolescent algorithms retained for backwards compatibility and historical value:
//       MD2, MD4, MD5, Panama Hash, DES (wired, see legacy table above),
//       ARC4/RC4 (wired, see legacy table above), SEAL 3.0, WAKE-OFB, DESX (DES-XEX3),
//       RC2 (wired, see legacy table above), SAFER, 3-WAY, GOST, SHARK, CAST-128, Square
//
// ================================================================================================

// microsoft
// 
// ================================================================================================
// WINDOWS -- full algorithm surface, LEGACY and CURRENT libraries listed SEPARATELY (not merged).
// Unlike the tables above, this section is not limited to encryption/decryption -- it lists
// everything each Windows crypto API exposes, because the two APIs are being catalogued as a
// whole, not per-category.
// ================================================================================================

// ------------------------------------------------------------------------------------------------
// A) WINDOWS LEGACY CryptoAPI (CSP model) -- deprecated since Windows Vista, superseded by CNG (B)
//    below. This SDK's CMicrosoftProvider does NOT use this API at all (uses CNG only).
// ------------------------------------------------------------------------------------------------
//
//   CSP (pszProvider)                      Symmetric                    Asymmetric        Hash
//   -------------------------------------  ----------------------------  ---------------  --------------
//   MS_DEF_PROV (Base)                     RC2, RC4                      RSA (<=1024 bit)  MD5, SHA-1
//   MS_ENHANCED_PROV (Enhanced)            RC2, RC4, DES, 3DES           RSA (<=16384 bit) MD5, SHA-1
//   MS_ENH_RSA_AES_PROV (Enhanced RSA/AES) RC2, RC4, DES, 3DES,          RSA               MD2, MD4, MD5,
//                                          AES-128/192/256                                 SHA-1, HMAC
//   MS_STRONG_PROV (Strong)                RC2, RC4, 3DES                RSA               MD5, SHA-1
//   MS_DEF_DSS_PROV / MS_ENH_DSS_DH_PROV   --                            DSA, Diffie-Hellman SHA-1
//   MS_SCHANNEL_PROV (TLS/SSL only)        RC2, RC4, DES, 3DES           RSA               MD5, SHA-1
//
//   Critical limitation: CryptEncrypt/CryptDecrypt have NO AEAD concept at all (no nonce/tag
//   parameters anywhere in the API) -- even MS_ENH_RSA_AES_PROV's AES is CBC/ECB only, never
//   GCM/CCM. No SHA-2/SHA-3, no ECC (ECDSA/ECDH), no ChaCha/modern AEAD in this entire API family.
//
// ------------------------------------------------------------------------------------------------
// B) WINDOWS CNG (BCrypt) -- current/recommended API; this is what CMicrosoftProvider is built on.
// ------------------------------------------------------------------------------------------------
//
//   Symmetric block/stream ciphers (BCRYPT_xxx_ALGORITHM identifiers):
//       AES, DES, DESX, 3DES, 3DES_112 (2-key EDE), RC2, RC4
//
//   AEAD chaining modes (set via BCRYPT_CHAINING_MODE on the AES algorithm handle):
//       GCM, CCM                            -- no EAX/SIV/GCM-SIV/ChaCha20-Poly1305 in CNG at all
//
//   Non-AEAD chaining modes:
//       CBC, ECB, CFB                       -- no CTR, no OFB in CNG
//       XTS-AES                             -- separate algorithm identifier (BCRYPT_XTS_AES_ALGORITHM),
//                                              not a chaining-mode property; mainly for disk encryption
//
//   Hash algorithms:
//       MD2, MD4, MD5, SHA-1, SHA-256, SHA-384, SHA-512,
//       SHA3-256, SHA3-384, SHA3-512         -- SHA-3 only on newer Windows (11 24H2+ / Server 2025+)
//
//   MAC:
//       AES-GMAC, AES-CMAC, HMAC (any hash algorithm + BCRYPT_ALG_HANDLE_HMAC_FLAG)
//
//   Asymmetric / signature:
//       RSA, RSA_SIGN (legacy PKCS#1 signing variant), DSA, Diffie-Hellman (DH),
//       ECDSA (P256/P384/P521, plus a generic curve-parameterized form), ECDH (P256/P384/P521,
//       plus generic curve form) -- generic ECDSA/ECDH can be parameterized to curve25519 on
//       newer Windows, giving X25519/Ed25519-like curve math
//
//   Key derivation:
//       PBKDF2, HKDF, SP800-108 CTR HMAC, SP800-56A Concat, TLS1.1 PRF, TLS1.2 PRF
//
//   Random number generation:
//       RNG (system preferred RNG), RNG_FIPS186_DSA
//
// ================================================================================================
// C) CROSS-CHECK -- every distinct algorithm/primitive from (A) and (B) above, checked against the
// other three providers this SDK already integrates. "W" here means it is ALSO one of the rows
// already wired-and-tested in the tables earlier in this file; a plain "Y"/"N" here has the same
// meaning as everywhere else in this file (library capable / not capable, not independently
// re-verified for every cell).
// ================================================================================================
//
//   Algorithm/primitive          Windows source     CPP   Botan   OSSL
//   ------------------------     ---------------    ----  -----   ----
//   RC2                          CAPI + CNG         Y     N*      Y      (W for MS; see legacy table)
//   RC4 / ARC4                   CAPI + CNG         Y     Y       Y      (W for MS; see legacy table)
//   DES                          CAPI + CNG         Y     Y       Y      (W for MS; see legacy table)
//   Triple-DES (3DES)            CAPI + CNG         Y     Y       Y      (W for MS; see legacy table)
//   DESX                         CNG only           N     N       N
//   AES                          CNG only           Y     Y       Y      (W everywhere; see AEAD/legacy tables)
//   RSA                          CAPI + CNG         Y     Y       Y      (W for MS; see asymmetric table)
//   DSA                          CAPI + CNG         Y     Y       Y
//   Diffie-Hellman (DH)          CAPI + CNG         Y     Y       Y
//   ECDSA (P256/384/521)         CNG only           Y     Y       Y
//   ECDH (P256/384/521)          CNG only           Y     Y       Y
//   Ed25519 / X25519             CNG only (curve param on generic ECDSA/ECDH)   Y     Y     Y
//   MD2                          CAPI + CNG         Y     N*      Y*
//   MD4                          CAPI + CNG         Y     N*      Y*
//   MD5                          CAPI + CNG         Y     Y       Y
//   SHA-1                        CAPI + CNG         Y     Y       Y
//   SHA-256 / 384 / 512          CNG only           Y     Y       Y
//   SHA3-256 / 384 / 512         CNG only (new)     Y     Y       Y
//   AES-GMAC                     CNG only           Y     Y*      Y*
//   AES-CMAC                     CNG only           Y     Y       Y*
//   HMAC (any hash)              CAPI (SHA-1/MD5 only) + CNG (any hash)   Y   Y   Y
//   PBKDF2                       CNG only           Y     Y       Y      (already used internally by
//                                                                         CCryptoApi's password path)
//   HKDF                         CNG only           Y     Y       Y
//   SP800-108 CTR HMAC KDF       CNG only           N*    N*      N*
//   SP800-56A Concat KDF         CNG only           N*    N*      N*
//   TLS1.1 / TLS1.2 PRF          CNG only           N     N       Y*
//   RNG (system CSPRNG)          CAPI + CNG         Y     Y       Y      (already wired: IRandomSource)
//
// ================================================================================================

// botan3130
//
// ================================================================================================
// BOTAN 3.13.0 -- full algorithm surface (not limited to encryption/decryption). Some entries
// necessarily repeat what the encryption/decryption tables above already say -- that's expected,
// this section catalogues the whole library, not just what this SDK wires.
// ================================================================================================
//
//   Block ciphers:
//       AES, ARIA, Blowfish, CAST-128, Camellia, DES, DES-EDE (3DES), GOST 28147-89, IDEA,
//       Kuznyechik, Lion, Noekeon, SEED, Serpent, SHACAL2, SM4, Threefish-512, Twofish, XTEA
//
//   Stream ciphers:
//       ChaCha (variable rounds), Salsa20, RC4 (legacy module), SHAKE-128 (usable as a stream cipher)
//
//   Cipher modes:
//       ECB, CBC (PKCS7 / OneAndZeros / X9.23 / ESP padding), CFB, OFB, CTR-BE, XTS
//
//   AEAD:
//       GCM, CCM, EAX, SIV, GCM-SIV, ChaCha20Poly1305, OCB
//
//   Hash functions:
//       BLAKE2b, GOST-34.11, Keccak, MD4, MD5, RIPEMD-160, SHA-1, SHA-224/256/384/512,
//       SHA-512/256, SHA-3 (224/256/384/512), SHAKE-128/256 (as XOF), SM3, Skein-512,
//       Streebog (256/512), Tiger, Whirlpool, Comb4P (hash combiner)
//
//   Message authentication codes:
//       CBC-MAC, CMAC, GMAC, HMAC, KMAC, Poly1305, SipHash, X9.19-MAC
//
//   Public-key cryptography:
//       RSA, DSA, ElGamal, Diffie-Hellman (DH), ECDH, ECDSA, ECGDSA, ECKCDSA, Ed25519, Ed448,
//       X25519, X448, GOST 34.10-2012, SM2
//
//   Post-quantum (Botan 3.x):
//       Kyber / ML-KEM, FrodoKEM, Classic McEliece (KEMs); Dilithium / ML-DSA, SPHINCS+ (signatures);
//       XMSS (hash-based signatures)
//
//   Key derivation / password hashing:
//       HKDF, KDF1/KDF2 (X9.42 / IEEE 1363), SP800-56A, PBKDF2, Scrypt, Argon2 (2i/2d/2id), Bcrypt
//
//   Padding schemes for public-key systems:
//       PKCS#1 v1.5, OAEP, PSS, EME1
//
// ================================================================================================

// openssl402
//
// ================================================================================================
// OPENSSL 4.0.2 (EVP layer) -- full algorithm surface (not limited to encryption/decryption).
// Some entries necessarily repeat what the encryption/decryption tables above already say -- that's
// expected, this section catalogues the whole library, not just what this SDK wires.
// ================================================================================================
//
//   Block ciphers:
//       AES, ARIA, Camellia, CAST5, DES, 3DES (DES-EDE3), IDEA (if enabled at build time), SEED,
//       SM4, Blowfish (legacy provider), RC2 (legacy provider), RC5 (legacy provider, optional)
//
//   Stream ciphers:
//       RC4 (legacy provider), ChaCha20
//
//   AEAD:
//       GCM, CCM, ChaCha20-Poly1305, AES-SIV, AES-OCB (since 1.1.0)
//
//   Cipher modes:
//       ECB, CBC, CFB, OFB, CTR, XTS (AES-XTS), AES Key Wrap (RFC 3394, WRAP/WRAP-PAD)
//
//   Hash functions:
//       MD5, MD4 (legacy provider), SHA-1, SHA-224/256/384/512, SHA-512/224, SHA-512/256,
//       SHA3-224/256/384/512, SHAKE128/256, BLAKE2b512, BLAKE2s256, SM3, RIPEMD-160,
//       Whirlpool (legacy provider), MDC2 (legacy provider)
//
//   Message authentication codes:
//       HMAC, CMAC, GMAC, Poly1305, SipHash, KMAC128/256
//
//   Public-key cryptography:
//       RSA, DSA, Diffie-Hellman (DH), EC (ECDSA/ECDH via generic EC keys), Ed25519, Ed448,
//       X25519, X448 (native since 1.1.1), SM2
//
//   Post-quantum (recent OpenSSL 3.5+/4.x branches only -- Y* below, build-dependent):
//       ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+)
//
//   Key derivation:
//       PBKDF2, HKDF, Scrypt, SSKDF, X942KDF, X963KDF, KRB5KDF, TLS1-PRF, Argon2 (3.2+)
//
//   Padding schemes for public-key systems:
//       PKCS#1 v1.5, OAEP, PSS
//
// ================================================================================================

// Delphi Encryption Compendium
//
// ================================================================================================
// DELPHI ENCRYPTION COMPENDIUM (DEC) -- https://github.com/decfpc/DelphiEncryptionCompendium
// Not one of this SDK's four providers (it's a Pascal/Delphi library, not usable from this C++
// codebase directly) -- listed here purely as a reference point for what a comparable general-
// purpose crypto library exposes, and cross-checked against MS/CPP/Botan/OSSL like everything else
// in this file.
// ================================================================================================
//
//   DEC's own list, as given (not reorganized):
//
//   Symmetric ciphers:
//       Blowfish, Twofish, IDEA, Cast128, Cast256, Mars, RC2, RC4, RC5, RC6, Rijndael/AES,
//       Square, SCOP, Sapphire, 1DES, 2DES, 3DES, 2DDES, 3DDES, 3TDES, 3Way, Gost, Misty,
//       NewDES, Q128, SAFER, Shark, Skipjack, TEA, TEAN
//
//   Block cipher operation modes:
//       CTSx, CBCx, CFB8, CFBx, OFB8, OFBx, CFSx, ECBx
//       (DEC's own naming: the trailing "x" means "any block size", 8 means bit-level feedback;
//       these map conceptually to the CBC/CFB/OFB/ECB/CTS rows already listed earlier in this file)
//
//   Hash functions:
//       MD2, MD4, MD5, RipeMD128, RipeMD160, RipeMD256, RipeMD320, SHA, SHA1, SHA256, SHA384,
//       SHA512, Haval128, Haval160, Haval192, Haval224, Haval256, Tiger, Panama, Whirlpool,
//       Whirlpool1, Square, Snefru128, Snefru256, Sapphire
//
// ------------------------------------------------------------------------------------------------
// Cross-check against MS / CPP / Botan / OSSL. "1DES/2DES/3DES/2DDES/3DDES/3TDES" are DEC's own
// naming for single/double/triple-DES key-schedule variants -- not repeated as separate rows here,
// they are the DES/Triple-DES rows already covered earlier in this file. Same for plain
// "Rijndael/AES", "RC2", "RC4", "Gost" (GOST 28147-89) -- already covered above, not repeated.
// ------------------------------------------------------------------------------------------------
//
//   Algorithm                    MS    CPP   Botan   OSSL   Notes
//   ------------------------     ----  ----  -----   ----   ------------------------------------
//   RC5                          N     Y     N*      Y*     OpenSSL: legacy provider, optional build
//   Square (cipher)              N     N*    N*      N*     AES predecessor, rarely implemented now
//   SCOP                         N     N     N       N      DEC-specific, not found elsewhere
//   Sapphire (cipher/hash)       N     N     N       N      DEC-specific, not found elsewhere
//   3-Way                        N     Y     N       N
//   Misty (MISTY1)               N     N*    N*      N*     Low confidence across the board
//   NewDES                       N     N     N       N      DEC-specific, not found elsewhere
//   Q128                         N     N     N       N      DEC-specific, not found elsewhere
//   SAFER                        N     Y     N*      N
//   Shark                        N     Y     N       N
//   Skipjack                     N     Y     N       N
//   TEA                          N     Y     Y*      N      Botan ships XTEA, plain TEA uncertain
//   TEAN                         N     N     N       N      DEC-specific TEA variant
//   RipeMD-128/256/320           N     Y     N*      N*     Botan/OpenSSL: only RIPEMD-160 confirmed
//   RipeMD-160                   N     Y     Y       Y
//   Haval (128/160/192/224/256)  N     N     N       N      Not in CPP/Botan/OSSL's README/docs
//   Panama (hash)                N     Y*    N       N      CPP lists "Panama Hash" separately from
//                                                            the Panama stream cipher
//   Whirlpool                    N     Y     Y       Y*     OpenSSL: legacy provider
//   Whirlpool1 (pre-standard)    N     N     N       N      Superseded revision; not implemented
//   Snefru128 / Snefru256        N     N     N       N      DEC-specific, not found elsewhere
//
// ================================================================================================

// ================================================================================================
// VERIFIED AGAINST THE ACTUAL VENDORED SOURCE (not general library knowledge) -- checked by
// listing files under 3rdParty/openssl402/providers/implementations/{ciphers,digests}/ and
// 3rdParty/botan3130/src/lib/{block,hash,modes/aead,pubkey}/ in this exact repo checkout. Where
// this disagrees with a Y*/N*/Y/N cell earlier in this file, that earlier cell is WRONG and the
// line below is the correction (earlier cells are left as-is rather than hunted down and edited,
// to keep a clear trail of what was corrected and why).
// ================================================================================================
//
//   OpenSSL 4.0.2 (source-confirmed, file exists in providers/implementations/ciphers/):
//     AES-GCM-SIV           CORRECTION: earlier marked N for OSSL -- cipher_aes_gcm_siv.c EXISTS.
//                            OpenSSL DOES support AES-GCM-SIV in this build (Y, not wired here).
//     AES-OCB                Confirmed Y (cipher_aes_ocb.c)
//     CTS (ciphertext stealing) CORRECTION: earlier marked N for OSSL -- cipher_cts.c EXISTS (Y).
//     DESX                    Confirmed Y (cipher_desx.c) -- was correctly N in the DEC section
//                              (DEC doesn't list DESX at all, so no correction needed there)
//     RC5                     Confirmed Y, not Y* (cipher_rc5.c exists)
//     ARIA-CCM / ARIA-GCM     Confirmed Y (cipher_aria_ccm.c, cipher_aria_gcm.c) -- ARIA has AEAD
//                              modes too, not just plain block cipher use
//     SM4-CCM / SM4-GCM / SM4-XTS  Confirmed Y (cipher_sm4_ccm.c, cipher_sm4_gcm.c, cipher_sm4_xts.c)
//     No EAX cipher file found -> confirms EAX = N for OSSL (already correct above)
//     No Twofish/Serpent/MARS/RC6/Threefish cipher files -> confirms N for OSSL (already correct)
//     Tiger digest: no tiger file under digests/ -> confirms Tiger = N for OSSL (already correct)
//     Haval/Panama/Snefru digests: no matching files -> confirms N for OSSL (already correct)
//     ml_dsa_mu_prov.c EXISTS -> ML-DSA (Dilithium, post-quantum signature) is confirmed Y, not
//                              just "Y* build-dependent" as the post-quantum row said earlier
//
//   Botan 3.13.0 (source-confirmed, directory/file exists under src/lib/):
//     Twofish                 Confirmed Y (src/lib/block/twofish/twofish.cpp) -- matches existing W
//     Whirlpool                Confirmed Y (src/lib/hash/whirlpool/whirlpool.cpp)
//     Streebog (GOST R 34.11-2012)  Confirmed Y (src/lib/hash/streebog/streebog.cpp)
//     EAX / SIV / OCB (AEAD)  Confirmed Y (src/lib/modes/aead/{eax,siv,ocb}/*.cpp) -- matches
//                              existing W for EAX/SIV, Y for OCB
//     RSA                     Confirmed Y (src/lib/pubkey/rsa/rsa.cpp) -- matches existing Y
//     Dilithium / ML-DSA       Confirmed Y (src/lib/pubkey/dilithium/ml_dsa/*.cpp) -- also has the
//                              older dilithium_round3 variant and Classic McEliece (cmce_*.cpp),
//                              Ed448/X448 (curve448/*.cpp) -- Botan 3.13's PQC/modern-curve support
//                              is broader than the earlier post-quantum line suggested
//     CORRECTION: Tiger        earlier marked Y for Botan in the DEC cross-check table -- WRONG.
//                              No src/lib/hash/tiger/ directory exists; Botan 3.x removed Tiger
//                              (it was present in Botan 2.x). Correct value is N for Botan.
//     MARS / RC2 / RC5 / RC6   No matching directories under src/lib/block/ -- confirms N for all
//                              of these in Botan (RC2 was already N* in the main matrix; now
//                              confirmed plain N)
//     Threefish / XTEA         No matching directories found under src/lib/block/ either -- Botan
//                              3.13 does not appear to ship these (XTEA in particular was assumed
//                              Y* for Botan in the CryptoPP-derived table; correct to N)
//
//   Also source-confirmed while checking the above:
//     OpenSSL ML-KEM (Kyber, post-quantum KEM) Confirmed Y
//       (providers/implementations/kem/ml_kem_kem.c exists, alongside a generic RSA-KEM and EC-KEM)
//     Botan Ascon                              Confirmed Y as a HASH only
//       (src/lib/hash/ascon_hash256/) -- no Ascon AEAD cipher directory found under
//       src/lib/modes/aead/, so Ascon-128/128a as an authenticated cipher is NOT present in Botan
//       3.13 even though the hash variant is
//
// ================================================================================================

// ================================================================================================
// BOUNCY CASTLE (Java/C#) -- reference only, not a provider in this SDK (JVM/.NET, not usable from
// this C++ codebase directly). Source:
// https://www.bouncycastle.org/documentation/specification_interoperability/#algorithms-and-key-types
// ================================================================================================
//
//   Bouncy Castle's own list, as published:
//
//   Symmetric block ciphers:
//       AES, ARIA, Ascon, Camellia, CAST-5, CAST-6, DSTU 7624, GOST 28147, GOST 3412-2015, LEA,
//       RC2, RC5, SM4, TripleDES
//
//   Stream ciphers:
//       ChaCha20, Grain, HC, Salsa20
//
//   Hash functions & XOFs:
//       BLAKE2, BLAKE3, MD5, RIPEMD (128/160/256/320), SHA-1, SHA-2 family (224/256/384/512/
//       512-224/512-256), SHA-3 family (224/256/384/512), SHAKE (128/256), SM3, Tiger, Whirlpool,
//       Ascon Hash/XOF
//
//   Specialized hash functions:
//       cSHAKE-128/256, KMAC-128/256, ParallelHash-128/256, TupleHash-128/256
//
//   Public-key algorithms:
//       RSA, DSA, ECDSA/ECDH, EdDSA/XDH (Curve25519/448), ElGamal, GOST, SM2,
//       Diffie-Hellman, DSTU 4145-2002
//
//   Hash-based digital signatures:
//       LMS/HSS, XMSS
//
//   Post-quantum, standardized (FIPS 203/204/205):
//       ML-DSA, ML-KEM, SLH-DSA
//
//   Post-quantum, experimental:
//       BIKE, HQC, Classic McEliece, SABER, FrodoKEM, NTRU, NTRU Prime, Falcon, Picnic, Rainbow, GeMSS
//
// ------------------------------------------------------------------------------------------------
// Cross-check: only algorithms NOT already covered by an earlier table in this file. DSTU 7624 is
// Kalyna (already listed under Crypto++), GOST 3412-2015 is Kuznyechik (already listed under
// Botan), Classic McEliece and FrodoKEM are already listed under Botan's post-quantum section,
// ML-DSA/ML-KEM/SLH-DSA already covered under the Windows/OpenSSL/Botan cross-checks above.
// ------------------------------------------------------------------------------------------------
//
//   Algorithm                    CPP   Botan   OSSL   Notes
//   ------------------------     ----  -----   ----   ------------------------------------
//   Ascon (AEAD cipher)          N     N       N*     Botan only has Ascon as a hash (see above);
//                                                       OpenSSL 4.0.2's KEM directory suggests active
//                                                       PQC work but no Ascon AEAD found -> N*
//   Ascon (hash/XOF)             N     Y       N
//   Grain (stream cipher)        N     N       N      eSTREAM finalist, not in any of our 3
//   HC (HC-128/256 stream)       N     N       N      eSTREAM finalist, not in any of our 3
//   BLAKE3                       N     N*      N*     Newer than all 3 libraries' typical hash sets
//   cSHAKE-128/256                N*    N*      Y      OpenSSL: cshake_prov.c exists (source-confirmed)
//   KMAC-128/256                  N*    Y       Y*     Botan lists KMAC as a MAC; OpenSSL likely via EVP_MAC
//   ParallelHash / TupleHash      N     N       N*     SHA-3-family extras, not commonly implemented
//   DSTU 4145-2002 (EC signature) N     N       N      Ukrainian national standard, rare outside BC
//   LMS/HSS (hash-based sig)      N     N*      N*     XMSS is more commonly implemented than LMS/HSS
//   BIKE / HQC / SABER            N     N       N      Round 3/4 PQC candidates not standardized;
//                                                       none of our 3 libraries ship these
//   NTRU / NTRU Prime             N     N       N*     libgcrypt ships SNTRUP761 (see below), but
//                                                       CPP/Botan/OSSL do not appear to
//   Falcon / Picnic / Rainbow /   N     N       N      Not standardized (Rainbow was broken), not
//   GeMSS                                              found in any of our 3 libraries
//
// ================================================================================================

// ================================================================================================
// LIBGCRYPT (GnuPG's crypto library) -- reference only, not a provider in this SDK (GPL-licensed,
// C library, but not vendored here). Source: https://www.gnupg.org/software/libgcrypt/index.html
// ================================================================================================
//
//   Libgcrypt's own list, as published:
//
//   Symmetric block ciphers:
//       AES, Blowfish, Camellia, CAST5, DES, GOST28147, Serpent, Twofish
//
//   Stream ciphers:
//       Arcfour (RC4), ChaCha20, Salsa20
//
//   Cipher modes:
//       ECB, CFB, CBC, OFB, CTR, CCM, GCM, OCB, POLY1305, AESWRAP
//
//   Hash algorithms:
//       MD2, MD4, MD5, GOST R 34.11 (1994 variant, distinct from Streebog/34.11-2012), RIPE-MD160,
//       SHA-1, SHA2-224/256/384/512, SHA3-224/256/384/512, SHAKE-128/256, TIGER-192, Whirlpool
//
//   Message authentication codes:
//       HMAC (all hash algorithms), CMAC (all ciphers), GMAC-AES/Camellia/Twofish/Serpent/SEED,
//       Poly1305, Poly1305-AES/Camellia/Twofish/Serpent/SEED
//
//   Public-key algorithms:
//       RSA, ElGamal, DSA, ECDSA, EdDSA, ECDH, ML-DSA, ML-KEM, SNTRUP761, Classic McEliece
//
// ------------------------------------------------------------------------------------------------
// Cross-check: virtually everything here already appears in an earlier table (this list overlaps
// heavily with the CryptoPP/Botan/OpenSSL/Windows sections above -- expected, since libgcrypt is a
// similarly general-purpose library). Only genuinely new items:
// ------------------------------------------------------------------------------------------------
//
//   Algorithm                    CPP   Botan   OSSL   Notes
//   ------------------------     ----  -----   ----   ------------------------------------
//   AESWRAP (AES key wrap)        N*    N*      Y      OpenSSL: cipher_aes_wrp.c (source-confirmed)
//   SNTRUP761 (NTRU Prime param)  N     N       N      Not found in CPP/Botan/OSSL
//   GOST R 34.11 (1994, plain)    N*    N*      N*     Distinct from Streebog/34.11-2012 (which Botan
//                                                       does have, source-confirmed above)
//
// ================================================================================================

#endif
