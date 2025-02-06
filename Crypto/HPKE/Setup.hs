{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

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
--   This throws 'HpkeError'.
setupBaseS
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedPublicKey
    -> Info
    -> IO (EncodedPublicKey, ContextS)
setupBaseS kem_id kdf_id aead_id pkRm info =
    setupBS defaultHPKEMap ModeBase kem_id kdf_id aead_id pkRm info "" ""

-- | Setting up base mode for a sender with its key pair.
--   This throws 'HpkeError'.
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
    setupBS' defaultHPKEMap ModeBase kem_id kdf_id aead_id skEm pkEm pkRm info "" ""

-- | Setting up base mode for a receiver with its key pair.
--   This throws 'HpkeError'.
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
    setupBR defaultHPKEMap ModeBase kem_id kdf_id aead_id skRm pkRm enc info "" ""

----------------------------------------------------------------

-- | Setting up PSK mode for a sender.
--   This throws 'HpkeError'.
setupPSKS
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedPublicKey
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupPSKS = setupBS defaultHPKEMap ModePsk

-- | Setting up PSK mode for a sender with its key pair.
--   This throws 'HpkeError'.
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
setupPSKS' = setupBS' defaultHPKEMap ModePsk

-- | Setting up PSK mode for a receiver with its key pair.
--   This throws 'HpkeError'.
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
setupPSKR = setupBR defaultHPKEMap ModePsk

----------------------------------------------------------------

setupBS
    :: HPKEMap
    -> Mode
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedPublicKey
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupBS hpkeMap mode kem_id kdf_id aead_id pkRm info psk psk_id =
    withHpkeMap hpkeMap mode kem_id kdf_id aead_id info psk psk_id $ \(KEMGroup group) derive schedule seal' _ -> do
        encap <- encapGen group derive
        case encap pkRm of
            Left err -> E.throwIO err
            Right (shared_secret, enc) -> do
                let quad = schedule shared_secret
                ctx <- newContextS quad seal'
                return (enc, ctx)

setupBS'
    :: HPKEMap
    -> Mode
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
setupBS' hpkeMap mode kem_id kdf_id aead_id skEm pkEm pkRm info psk psk_id =
    withHpkeMap hpkeMap mode kem_id kdf_id aead_id info psk psk_id $ \(KEMGroup group) derive schedule seal' _ -> do
        let encap = encapEnv group derive skEm pkEm
        case encap pkRm of
            Left err -> E.throwIO err
            Right (shared_secret, enc) -> do
                let quad = schedule shared_secret
                ctx <- newContextS quad seal'
                return (enc, ctx)

setupBR
    :: HPKEMap
    -> Mode
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
setupBR hpkeMap mode kem_id kdf_id aead_id skRm pkRm enc info psk psk_id =
    withHpkeMap hpkeMap mode kem_id kdf_id aead_id info psk psk_id $ \(KEMGroup group) derive schedule _ open' -> do
        let decap = decapEnv group derive skRm pkRm
        case decap enc of
            Left err -> E.throwIO err
            Right shared_secret -> do
                let quad = schedule shared_secret
                newContextR quad open'

----------------------------------------------------------------

look
    :: HPKEMap
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Either HpkeError ((KEMGroup, KDFHash), KDFHash, AeadCipher)
look HPKEMap{..} kem_id kdf_id aead_id = do
    k <- lookupE kem_id kemMap
    h <- lookupE kdf_id kdfMap
    a <- lookupE aead_id cipherMap
    return (k, h, a)

withHpkeMap
    :: HPKEMap
    -> Mode
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Info
    -> PSK
    -> PSK_ID
    -> ( KEMGroup
         -> KeyDeriveFunction
         -> (SharedSecret -> (ByteString, ByteString, Int, ByteString))
         -> (Key -> Seal)
         -> (Key -> Open)
         -> IO a
       )
    -> IO a
withHpkeMap hpkeMap mode kem_id kdf_id aead_id info psk psk_id body =
    case look hpkeMap kem_id kdf_id aead_id of
        Left err -> E.throwIO err
        Right ((group, KDFHash h), KDFHash h', AeadCipher c) -> do
            let suite = suiteKEM kem_id
                derive = extractAndExpand h suite
                nk = nK c
                nn = nN c
                seal' = sealA c
                open' = openA c
                suite' = suiteHPKE kem_id kdf_id aead_id
                schedule = keySchedule h' suite' nk nn mode info psk psk_id
            body group derive schedule seal' open'

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
