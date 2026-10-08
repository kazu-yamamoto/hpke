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

import Crypto.KEM (encapsulate, encapsulateWith, decapsulate)

import Crypto.HPKE.AEAD
import Crypto.HPKE.Context
import Crypto.HPKE.ID
import Crypto.HPKE.KDF
import Crypto.HPKE.KEM
import Crypto.HPKE.KeySchedule
import Crypto.HPKE.Map
import Crypto.HPKE.Types

-- | Setting up base/auth mode for a sender.
--   This throws 'HPKEError'.
setupBaseS
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Maybe EncodedSecretKey
    -- ^ My ephemeral secret key. Automatically generated if 'Nothing'
    -> Maybe EncodedSecretKey
    -- ^ My secret key for authentication.
    --   'mode_base' is used if 'Nothing'. 'base_auth' is used, otherwise.
    -> EncodedPublicKey
    -- ^ Peer's public key.
    -> Info
    -> IO (EncodedPublicKey, ContextS)
setupBaseS kem_id kdf_id aead_id mskEm mskSm pkRm info =
    setupS defaultHPKEMap mode kem_id kdf_id aead_id mskEm mskSm pkRm info "" ""
  where
    mode = case mskSm of
        Nothing -> ModeBase
        _ -> ModeAuth

-- | Setting up base/auth mode for a receiver with its key pair.
--   This throws 'HPKEError'.
setupBaseR
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey
    -- ^ My secret key
    -> Maybe EncodedPublicKey
    -- ^ The sender's public key, for authentication.
    --   'mode_base' is used if 'Nothing'. 'mode_auth' is used, otherwise.
    -> EncodedPublicKey
    -- ^ The encapsulated key, @enc@.
    -> Info
    -> IO ContextR
setupBaseR kem_id kdf_id aead_id skRm mpkSm enc info =
    setupR defaultHPKEMap mode kem_id kdf_id aead_id skRm mpkSm enc info "" ""
  where
    mode = case mpkSm of
        Nothing -> ModeBase
        _ -> ModeAuth

----------------------------------------------------------------

-- | Setting up psk/auth_psk mode for a sender.
--   This throws 'HPKEError'.
setupPSKS
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Maybe EncodedSecretKey
    -- ^ My ephemeral secret key. Automatically generated if 'Nothing'
    -> Maybe EncodedSecretKey
    -- ^ My secret key for authentication.
    --   'mode_base' is used if 'Nothing'. 'base_auth' is used, otherwise.
    -> EncodedPublicKey
    -- ^ Peer's public key.
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupPSKS kem_id kdf_id aead_id skRm mskSm =
    setupS defaultHPKEMap mode kem_id kdf_id aead_id skRm mskSm
  where
    mode = case mskSm of
        Nothing -> ModePsk
        _ -> ModeAuthPsk

-- | Setting up psk/auth_psk mode for a receiver with its key pair.
--   This throws 'HPKEError'.
setupPSKR
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedSecretKey
    -- ^ My secret key
    -> Maybe EncodedPublicKey
    -- ^ The sender's public key, for authentication.
    --   'mode_psk' is used if 'Nothing'. 'mode_auth_psk' is used, otherwise.
    -> EncodedPublicKey
    -- ^ The encapsulated key, @enc@.
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextR
setupPSKR kem_id kdf_id aead_id skRm mpkSm =
    setupR defaultHPKEMap mode kem_id kdf_id aead_id skRm mpkSm
  where
    mode = case mpkSm of
        Nothing -> ModePsk
        _ -> ModeAuthPsk

----------------------------------------------------------------

setupS
    :: HPKEMap
    -> Mode
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Maybe EncodedSecretKey
    -- ^ My ephemeral secret key. Automatically generated if 'Nothing'
    -> Maybe EncodedSecretKey
    -- ^ My secret key for authentication.
    --   'mode_base' is used if 'Nothing'. 'base_auth' is used, otherwise.
    -> EncodedPublicKey
    -- ^ Peer's public key.
    -> Info
    -> PSK
    -> PSK_ID
    -> IO (EncodedPublicKey, ContextS)
setupS hpkeMap mode kem_id kdf_id aead_id mskEm mskSm pkRm info psk psk_id = do
    verifyPSKInput mode psk psk_id
    let r = look hpkeMap kem_id kdf_id aead_id
    throwOnError r $ \(KEMAlg kem, KDFHash h', AEADCipher c) -> do
        encapped <- hpkeEncap kem mskEm mskSm pkRm
        throwOnError encapped $ \(enc, shared_secret) -> do
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
    -> EncodedSecretKey
    -- ^ My secret key
    -> Maybe EncodedPublicKey
    -- ^ The sender's public key, for the authenticated modes.
    -> EncodedPublicKey
    -- ^ The encapsulated key, @enc@.
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextR
setupR hpkeMap mode kem_id kdf_id aead_id skRm mpkSm enc info psk psk_id = do
    verifyPSKInput mode psk psk_id
    let r = look hpkeMap kem_id kdf_id aead_id
    throwOnError r $ \(KEMAlg kem, KDFHash h', AEADCipher c) -> do
        throwOnError (hpkeDecap kem skRm mpkSm enc) $ \shared_secret -> do
            let (nk, nn, _, open') = aeadParams c
                suite' = suiteHPKE kem_id kdf_id aead_id
                keys = keySchedule h' suite' nk nn mode info psk psk_id shared_secret
            throwOnError keys $ \(key, nonce, _, prk) -> do
                let expand' = labeledExpand suite' prk "sec"
                newContextR key nonce open' expand'

-- | The four ways RFC 9180 reaches a shared secret on the sending side.
-- The two unauthenticated ones are @crypton@'s 'encapsulate' and
-- 'encapsulateWith'; the two authenticated ones are what 'HPKEKEM' adds,
-- and a KEM without them refuses here rather than further down.
hpkeEncap
    :: HPKEKEM kem
    => proxy kem
    -> Maybe EncodedSecretKey
    -- ^ @skE@, drawn here if absent
    -> Maybe EncodedSecretKey
    -- ^ @skS@, which makes it an authenticated mode
    -> EncodedPublicKey
    -> IO (Either HPKEError (EncodedPublicKey, SharedSecret))
hpkeEncap kem mskEm mskSm pkRm = case (mskEm, mskSm) of
    (Nothing, Nothing) -> toHPKEError EncapError <$> encapsulate kem pkRm
    (Just skEm, Nothing) ->
        return $ toHPKEError EncapError $ encapsulateWith kem pkRm skEm
    (Nothing, Just skSm) -> do
        skEm <- generateCoins kem
        return $ authEncapWith kem skSm pkRm skEm
    (Just skEm, Just skSm) -> return $ authEncapWith kem skSm pkRm skEm

-- | And the two on the receiving side.
hpkeDecap
    :: HPKEKEM kem
    => proxy kem
    -> EncodedSecretKey
    -> Maybe EncodedPublicKey
    -- ^ @pkS@, which makes it an authenticated mode
    -> EncodedPublicKey
    -> Either HPKEError SharedSecret
hpkeDecap kem skRm Nothing enc =
    toHPKEError DecapError $ decapsulate kem skRm enc
hpkeDecap kem skRm (Just pkSm) enc = authDecap kem pkSm skRm enc

-- | The class answers with a 'CryptoFailable', which has a reason and no
-- message.  Everything above here wants an 'HPKEError', so the reason is
-- spelled back out.
toHPKEError :: (String -> HPKEError) -> CryptoFailable a -> Either HPKEError a
toHPKEError _ (CryptoPassed a) = Right a
toHPKEError con (CryptoFailed e) = Left $ con $ show e

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
    -> Either HPKEError (KEMAlg, KDFHash, AEADCipher)
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

suiteHPKE :: KEM_ID -> KDF_ID -> AEAD_ID -> Suite
suiteHPKE kem_id hkdf_id aead_id = "HPKE" <> i0 <> i1 <> i2
  where
    i0 = i2ospOf_ 2 $ fromIntegral $ fromKEM_ID kem_id
    i1 = i2ospOf_ 2 $ fromIntegral $ fromKDF_ID hkdf_id
    i2 = i2ospOf_ 2 $ fromIntegral $ fromAEAD_ID aead_id
