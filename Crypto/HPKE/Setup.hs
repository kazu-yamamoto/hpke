{-# LANGUAGE OverloadedStrings #-}

module Crypto.HPKE.Setup (
    setupBaseS,
    setupBaseS',
    setupBaseR,
    setupPSKS,
    setupPSKS',
    setupPSKR,
) where

import Crypto.HPKE.ID
import Crypto.HPKE.KEM
import Crypto.HPKE.KeySchedule
import Crypto.HPKE.Types

-- | Setting up base mode for a sender.
setupBaseS
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedPublicKey
    -> Info
    -> IO (EncodedPublicKey, ContextS)
setupBaseS kem_id kdf_id aead_id pkRm info =
    setupBS ModeBase kem_id kdf_id aead_id pkRm info "" ""

-- | Setting up base mode for a sender with its key pair.
setupBaseS'
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey -- mine
    -> EncodedPublicKey -- mine
    -> EncodedPublicKey -- peer
    -> Info
    -> IO (EncodedPublicKey, ContextS)
setupBaseS' kem_id kdf_id aead_id skEm pkEm pkRm info =
    setupBS' ModeBase kem_id kdf_id aead_id skEm pkEm pkRm info "" ""

-- | Setting up base mode for a receiver with its key pair.
setupBaseR
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey -- mine
    -> EncodedPublicKey -- mine
    -> EncodedPublicKey -- peer
    -> Info
    -> IO ContextR
setupBaseR kem_id kdf_id aead_id skRm pkRm enc info =
    setupBR ModeBase kem_id kdf_id aead_id skRm pkRm enc info "" ""

----------------------------------------------------------------

-- | Setting up PSK mode for a sender.
setupPSKS
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedPublicKey
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupPSKS kem_id kdf_id aead_id pkRm info psk psk_id =
    setupBS ModePsk kem_id kdf_id aead_id pkRm info psk psk_id

-- | Setting up PSK mode for a sender with its key pair.
setupPSKS'
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey -- mine
    -> EncodedPublicKey -- mine
    -> EncodedPublicKey -- peer
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupPSKS' kem_id kdf_id aead_id skEm pkEm pkRm info psk psk_id =
    setupBS' ModePsk kem_id kdf_id aead_id skEm pkEm pkRm info psk psk_id

-- | Setting up PSK mode for a receiver with its key pair.
setupPSKR
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey -- mine
    -> EncodedPublicKey -- mine
    -> EncodedPublicKey -- peer
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextR
setupPSKR kem_id kdf_id aead_id skRm pkRm enc info psk psk_id =
    setupBR ModePsk kem_id kdf_id aead_id skRm pkRm enc info psk psk_id

----------------------------------------------------------------

setupBS
    :: Mode
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedPublicKey
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupBS mode kem_id kdf_id aead_id pkRm info psk psk_id = do
    encap <- encapGen kem_id
    let (shared_secret, enc) = encap pkRm
    ctx <-
        keyScheduleS kem_id kdf_id aead_id mode shared_secret info psk psk_id
    return (enc, ctx)

setupBS'
    :: Mode
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey -- mine
    -> EncodedPublicKey -- mine
    -> EncodedPublicKey -- peer
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupBS' mode kem_id kdf_id aead_id skEm pkEm pkRm info psk psk_id = do
    let encap = encapKEM kem_id skEm pkEm
        (shared_secret, enc) = encap pkRm
    ctx <- keyScheduleS kem_id kdf_id aead_id mode shared_secret info psk psk_id
    return (enc, ctx)

setupBR
    :: Mode
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey -- mine
    -> EncodedPublicKey -- mine
    -> EncodedPublicKey -- peer
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextR
setupBR mode kem_id kdf_id aead_id skRm pkRm enc info psk psk_id = do
    let shared_secret = decapKEM kem_id skRm pkRm enc
    keyScheduleR kem_id kdf_id aead_id mode shared_secret info psk psk_id
