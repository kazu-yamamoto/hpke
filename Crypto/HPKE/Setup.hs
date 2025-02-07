{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.Setup (
    setupBaseS,
    setupBaseR,
    setupPSKS,
    setupPSKR,
    setupS,
    setupR,
) where

import qualified Control.Exception as E

import Crypto.HPKE.AEAD
import Crypto.HPKE.Context
import Crypto.HPKE.ID
import Crypto.HPKE.KDF
import Crypto.HPKE.KEM
import Crypto.HPKE.KeySchedule
import Crypto.HPKE.Types

-- | Setting up base mode for a sender.
--   This throws 'HPKEError'.
setupBaseS
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Maybe EncodedSecretKey -- mine, gen if Nothing
    -> Maybe EncodedSecretKey -- mine, auth if Just
    -> EncodedPublicKey -- peer
    -> Info
    -> IO (EncodedPublicKey, ContextS)
setupBaseS kem_id kdf_id aead_id mskEm mskSm pkRm info =
    setupS defaultHPKEMap ModeBase kem_id kdf_id aead_id mskEm mskSm pkRm info "" ""

-- | Setting up base mode for a receiver with its key pair.
--   This throws 'HPKEError'.
setupBaseR
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey -- mine
    -> Maybe EncodedSecretKey -- mine, auth if Just
    -> EncodedPublicKey -- peer
    -> Info
    -> IO ContextR
setupBaseR kem_id kdf_id aead_id skRm mskSm enc info =
    setupR defaultHPKEMap ModeBase kem_id kdf_id aead_id skRm mskSm enc info "" ""

----------------------------------------------------------------

-- | Setting up PSK mode for a sender.
--   This throws 'HPKEError'.
setupPSKS
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Maybe EncodedSecretKey -- mine, gen if Nothing
    -> Maybe EncodedSecretKey -- mine, auth if Just
    -> EncodedPublicKey -- peer
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupPSKS = setupS defaultHPKEMap ModePsk

-- | Setting up PSK mode for a receiver with its key pair.
--   This throws 'HPKEError'.
setupPSKR
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey -- mine
    -> Maybe EncodedSecretKey -- mine, auth if Just
    -> EncodedPublicKey -- peer
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextR
setupPSKR = setupR defaultHPKEMap ModePsk

----------------------------------------------------------------

setupS
    :: HPKEMap
    -> Mode
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Maybe EncodedSecretKey -- mine
    -> Maybe EncodedSecretKey -- mine (auth)
    -> EncodedPublicKey -- peer
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupS hpkeMap mode kem_id kdf_id aead_id mskEm mskSm pkRm info psk psk_id = do
    verifyPSKInput mode psk psk_id
    let r = look hpkeMap kem_id kdf_id aead_id
    throwOnError r $ \((KEMGroup group, KDFHash h), KDFHash h', AEADCipher c) -> do
        let derive = extractAndExpand h $ suiteKEM kem_id
        encap <- case mskEm of
            Nothing -> encapGen group derive mskSm
            Just skEm -> return $ encapEnv group derive skEm mskSm
        throwOnError (encap pkRm) $ \(shared_secret, enc) -> do
            let (nk, nn, seal', _) = aeadParams c
                suite' = suiteHPKE kem_id kdf_id aead_id
                keys = keySchedule h' suite' nk nn mode info psk psk_id shared_secret
            throwOnError keys $ \(key, nonce, _, prk) -> do
                let expand' = labeledExpand suite' prk "sec"
                ctx <- newContextS key nonce seal' expand'
                return (enc, ctx)

setupR
    :: HPKEMap
    -> Mode
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey -- mine
    -> Maybe EncodedSecretKey -- mine
    -> EncodedPublicKey -- peer
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextR
setupR hpkeMap mode kem_id kdf_id aead_id skRm mskSm enc info psk psk_id = do
    verifyPSKInput mode psk psk_id
    let r = look hpkeMap kem_id kdf_id aead_id
    throwOnError r $ \((KEMGroup group, KDFHash h), KDFHash h', AEADCipher c) -> do
        let derive = extractAndExpand h $ suiteKEM kem_id
            decap = decapEnv group derive skRm mskSm
        throwOnError (decap enc) $ \shared_secret -> do
            let (nk, nn, _, open') = aeadParams c
                suite' = suiteHPKE kem_id kdf_id aead_id
                keys = keySchedule h' suite' nk nn mode info psk psk_id shared_secret
            throwOnError keys $ \(key, nonce, _, prk) -> do
                let expand' = labeledExpand suite' prk "sec"
                newContextR key nonce open' expand'

aeadParams
    :: Aead a
    => Proxy a -> (Int, Int, Key -> Seal, Key -> Open)
aeadParams c = (nK c, nN c, sealA c, openA c)

throwOnError :: Either HPKEError v -> (v -> IO a) -> IO a
throwOnError (Left err) _body = E.throwIO err
throwOnError (Right ss) body = body ss

----------------------------------------------------------------

look
    :: HPKEMap
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Either HPKEError ((KEMGroup, KDFHash), KDFHash, AEADCipher)
look HPKEMap{..} kem_id kdf_id aead_id = do
    k <- lookupE kem_id kemMap
    h <- lookupE kdf_id kdfMap
    a <- lookupE aead_id cipherMap
    return (k, h, a)

verifyPSKInput :: Mode -> PSK -> PSK_ID -> IO ()
verifyPSKInput mode psk psk_id
    | got_psk /= got_psk_id =
        E.throwIO $ ValidationError "mismatch for psk and psk_id"
    | got_psk && mode `elem` [ModeBase, ModeAuth] =
        E.throwIO $ ValidationError "invalid mode (1)"
    | (not got_psk) && mode `elem` [ModePsk, ModeAuthPsk] =
        E.throwIO $ ValidationError "invalid mode (2)"
    | otherwise = return ()
  where
    got_psk = psk /= ""
    got_psk_id = psk_id /= ""

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
