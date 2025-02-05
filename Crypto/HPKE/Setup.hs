{-# LANGUAGE OverloadedStrings #-}

module Crypto.HPKE.Setup (
    setupBaseS,
    setupBaseS',
    setupBaseR,
    setupPSKS,
    setupPSKS',
    setupPSKR,
) where

import qualified Control.Exception as E

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
setupPSKS = setupBS ModePsk

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
setupPSKS' = setupBS' ModePsk

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
setupPSKR = setupBR ModePsk

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
    case encap pkRm of
        Left err -> E.throwIO err
        Right (shared_secret, enc) -> do
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
    case encap pkRm of
        Left err -> E.throwIO err
        Right (shared_secret, enc) -> do
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
    case decapKEM kem_id skRm pkRm enc of
        Left err -> E.throwIO err
        Right shared_secret -> keyScheduleR kem_id kdf_id aead_id mode shared_secret info psk psk_id
