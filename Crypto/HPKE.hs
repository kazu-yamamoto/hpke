-- | Hybrid Public Key Encryption (RFC9180).
module Crypto.HPKE (
    -- * IDs
    KEM_ID (..),
    KDF_ID (..),
    AEAD_ID (..),

    -- * Setup

    -- ** Base
    setupBaseS,
    setupBaseR,

    -- ** PSK setup
    setupPSKS,
    setupPSKR,

    -- * Encryption and Decyption
    seal,
    open,

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

    -- * Error
    HPKEError (..),
) where

import Crypto.HPKE.Context
import Crypto.HPKE.ID
import Crypto.HPKE.Setup
import Crypto.HPKE.Types
