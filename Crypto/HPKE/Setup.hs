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

import Crypto.HPKE.AEAD
import Crypto.HPKE.ID
import Crypto.HPKE.KDF
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
setupBS mode kem_id kdf_id aead_id pkRm info psk psk_id =
    case look kem_id kdf_id aead_id of
        Left err -> E.throwIO err
        Right ((KEMGroup group, KDFHash h), KDFHash h', AeadCipher c) -> do
            let suite = suiteKEM kem_id
                derive = extractAndExpandH h suite
            encap <- encapGen group derive
            case encap pkRm of
                Left err -> E.throwIO err
                Right (shared_secret, enc) -> do
                    let seal' = sealA c
                        nk = nK c
                        nn = nN c
                        suite' = suiteHPKE kem_id kdf_id aead_id
                    let quad = keySchedule h' nk nn mode suite' shared_secret info psk psk_id
                    ctx <- newContextS quad seal'
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
setupBS' mode kem_id kdf_id aead_id skEm pkEm pkRm info psk psk_id =
    case look kem_id kdf_id aead_id of
        Left err -> E.throwIO err
        Right ((KEMGroup group, KDFHash h), KDFHash h', AeadCipher c) -> do
            let suite = suiteKEM kem_id
                derive = extractAndExpandH h suite
                encap = encapKEM group derive skEm pkEm
            case encap pkRm of
                Left err -> E.throwIO err
                Right (shared_secret, enc) -> do
                    let seal' = sealA c
                        nk = nK c
                        nn = nN c
                        suite' = suiteHPKE kem_id kdf_id aead_id
                    let quad = keySchedule h' nk nn mode suite' shared_secret info psk psk_id
                    ctx <- newContextS quad seal'
                    return (enc, ctx)

look
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Either HpkeError ((KEMGroup, KDFHash), KDFHash, AeadCipher)
look kem_id kdf_id aead_id = do
    k <- lookupE kem_id defaultKemMap
    h <- lookupE kdf_id defaultKdfMap
    a <- lookupE aead_id defaultCipherMap
    return (k, h, a)

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
    case look kem_id kdf_id aead_id of
        Left err -> E.throwIO err
        Right ((KEMGroup group, KDFHash h), KDFHash h', AeadCipher c) -> do
            let suite = suiteKEM kem_id
                derive = extractAndExpandH h suite
                decap = decapKEM group derive skRm pkRm
            case decap enc of
                Left err -> E.throwIO err
                Right shared_secret -> do
                    let open' = openA c
                        nk = nK c
                        nn = nN c
                        suite' = suiteHPKE kem_id kdf_id aead_id
                    let quad = keySchedule h' nk nn mode suite' shared_secret info psk psk_id
                    newContextR quad open'

----------------------------------------------------------------

suiteKEM :: KEM_ID -> Suite
suiteKEM kem_id = "KEM" <> i
  where
    i = i2ospOf_ 2 $ fromIntegral $ fromKEM_ID kem_id

suiteHPKE :: KEM_ID -> KDF_ID -> AEAD_ID -> Suite
suiteHPKE kem_id hkdf_id aead_id = "HPKE" <> i0 <> i1 <> i2
  where
    i0 = i2ospOf_ 2 $ fromIntegral $ fromKEM_ID kem_id
    i1 = i2ospOf_ 2 $ fromIntegral $ fromKDF_ID hkdf_id
    i2 = i2ospOf_ 2 $ fromIntegral $ fromAEAD_ID aead_id
