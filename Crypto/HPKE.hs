-- | Hybrid Public Key Encryption (RFC9180).
module Crypto.HPKE (
    -- * IDs
    KEM_ID (..),
    KDF_ID (..),
    AEAD_ID (..),

    -- * Setup

    -- ** Base
    setupBaseS,
    setupBaseS',
    setupBaseR,

    -- ** PSK setup
    setupPSKS,
    setupPSKS',
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
    HpkeError (..),
) where

import Crypto.HPKE.Context
import Crypto.HPKE.ID
import Crypto.HPKE.Setup
import Crypto.HPKE.Types
