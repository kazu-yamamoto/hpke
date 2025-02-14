-- | Hybrid Public Key Encryption (RFC9180).
module Crypto.HPKE (
    -- * IDs
    KEM_ID (..),
    KDF_ID (..),
    AEAD_ID (..),

    -- * Setup

    -- ** For mode_base and mode_auth
    setupBaseS,
    setupBaseR,

    -- ** For mode_psk and mode_auth_psk
    setupPSKS,
    setupPSKR,

    -- * Encryption and Decyption
    seal,
    open,

    -- * Secret export
    exportS,
    exportR,

    -- * Types
    ContextS,
    ContextR,
    EncodedSecretKey (..),
    EncodedPublicKey (..),
    SharedSecret (..),
    Info,
    PSK,
    PSK_ID,
    AAD,
    PlainText,
    CipherText,
    Key,

    -- * Error
    HPKEError (..),

    -- * Misc
    nEnc,
) where

import Crypto.HPKE.Context
import Crypto.HPKE.ID
import Crypto.HPKE.Setup
import Crypto.HPKE.Types

-- | Length of "enc", aka sender's public key.
{- FOURMOLU_DISABLE -}
nEnc :: KEM_ID -> Int
nEnc DHKEM_P256_HKDF_SHA256   =  65
nEnc DHKEM_P384_HKDF_SHA384   =  97
nEnc DHKEM_P521_HKDF_SHA512   = 133
nEnc DHKEM_X25519_HKDF_SHA256 =  32
nEnc DHKEM_X448_HKDF_SHA512   =  56
nEnc _                        =  0
{- FOURMOLU_ENABLE -}
