{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Crypto.HPKE (
    -- * Base setup
    setupBaseS,
    setupBaseS',
    setupBaseR,
    KEM_ID (
        DHKEM_P256_HKDF_SHA256,
        DHKEM_P384_HKDF_SHA384,
        DHKEM_P512_HKDF_SHA512,
        DHKEM_X25519_HKDF_SHA256,
        DHKEM_X448_HKDF_SHA512,
        ..
    ),
    KDF_ID (HKDF_SHA256, HKDF_SHA384, HKDF_SHA512, ..),
    AEAD_ID (AES_128_GCM, AES_256_GCM, ChaCha20Poly1305),
    EncodedSecretKey (..),
    EncodedPublicKey (..),
    SharedSecret (..),
    Info,
    ContextS,
    ContextR,

    -- * PSK setup
    setupPSKS,
    setupPSKS',
    setupPSKR,
    PSK,
    PSK_ID,

    -- * Encryption and Decyption
    seal,
    open,
    AssociatedData,
    PlainText,
    CipherText,
) where

import Crypto.HPKE.ID
import Crypto.HPKE.KeySchedule
import Crypto.HPKE.Setup
import Crypto.HPKE.Types
