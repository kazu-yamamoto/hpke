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
) where

import Crypto.HPKE.Context
import Crypto.HPKE.ID
import Crypto.HPKE.Setup
import Crypto.HPKE.Types
