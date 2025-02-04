{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KeySchedule (
    -- * Mode
    Mode (..),

    -- * Sender
    ContextS,
    keyScheduleS,
    seal,

    -- * Receiver
    ContextR,
    keyScheduleR,
    open,
) where

import Data.ByteArray (xor)
import qualified Data.ByteString as BS
import Data.IORef
import Data.Word

import Crypto.HPKE.AEAD
import Crypto.HPKE.ID
import Crypto.HPKE.KDF
import Crypto.HPKE.Types

----------------------------------------------------------------

data Mode
    = ModeBase
    | ModePsk
    | ModeAuth
    | ModeAuthPsk
    deriving (Eq, Show)

{- FOURMOLU_DISABLE -}
fromMode :: Mode -> Word8
fromMode ModeBase    = 0x00
fromMode ModePsk     = 0x01
fromMode ModeAuth    = 0x02
fromMode ModeAuthPsk = 0x03
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

-- | Context for senders.
data ContextS = ContextS
    { seqRefS :: IORef Integer
    , sealS :: SealK
    , nonceBaseS :: Nonce
    }

-- | Context for receivers.
data ContextR = ContextR
    { seqRefR :: IORef Integer
    , openR :: OpenK
    , nonceBaseR :: Nonce
    }

----------------------------------------------------------------

-- | Encryption.
seal :: ContextS -> AssociatedData -> PlainText -> IO CipherText
seal ContextS{..} aad pt = do
    seqI <- readIORef seqRefS
    let len = BS.length nonceBaseS
        seqBS = i2ospOf_ len seqI :: ByteString
        nonce = seqBS `xor` nonceBaseS
        ct = sealS nonce aad pt
        seqI' = seqI + 1
    writeIORef seqRefS seqI'
    return ct

-- | Decryption.
open :: ContextR -> AssociatedData -> CipherText -> IO PlainText
open ContextR{..} aad ct = do
    seqI <- readIORef seqRefR
    let len = BS.length nonceBaseR
        seqBS = i2ospOf_ len seqI :: ByteString
        nonce = seqBS `xor` nonceBaseR
        Right pt = openR nonce aad ct -- fixme
        seqI' = seqI + 1
    writeIORef seqRefR seqI'
    return pt

----------------------------------------------------------------

keyScheduleS
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Mode
    -> SharedSecret
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextS
keyScheduleS kem_id kdf_id aead_id = new seal' ns suite_id
  where
    suite_id = suiteHPKE kem_id kdf_id aead_id
    new = case kdf_id of
        HKDF_SHA256 -> keyScheduleS' SHA256
        HKDF_SHA384 -> keyScheduleS' SHA256
        HKDF_SHA512 -> keyScheduleS' SHA512
        _ -> error "keyScheduleS"
    seal' = case aead_id of
        AES_128_GCM -> sealA (Proxy :: Proxy AES128)
        AES_256_GCM -> sealA (Proxy :: Proxy AES256)
        ChaCha20Poly1305 -> sealA (Proxy :: Proxy ChaCha20Poly1305)
        _ -> error "keyScheduleS"
    ns = case aead_id of
        AES_128_GCM -> let proxy = Proxy :: Proxy AES128 in (nK proxy, nN proxy)
        AES_256_GCM -> let proxy = Proxy :: Proxy AES256 in (nK proxy, nN proxy)
        ChaCha20Poly1305 -> let proxy = Proxy :: Proxy ChaCha20Poly1305 in (nK proxy, nN proxy)
        _ -> error "keyScheduleS"

keyScheduleS'
    :: ( HashAlgorithm h
       , KDF h
       )
    => h
    -> Seal
    -> (Int, Int)
    -> Suite
    -> Mode
    -> SharedSecret
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextS
keyScheduleS' h seal' ns suite mode shared_secret info psk psk_id = do
    seqref <- newIORef 0
    let (key, nonce_base, _, _) = keySchedule h ns mode suite shared_secret info psk psk_id
    return $
        ContextS
            { seqRefS = seqref
            , sealS = seal' key
            , nonceBaseS = nonce_base
            }

----------------------------------------------------------------

keyScheduleR
    :: KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> Mode
    -> SharedSecret
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextR
keyScheduleR kem_id kdf_id aead_id = new open' ns suite_id
  where
    suite_id = suiteHPKE kem_id kdf_id aead_id
    new = case kdf_id of
        HKDF_SHA256 -> keyScheduleR' SHA256
        HKDF_SHA384 -> keyScheduleR' SHA256
        HKDF_SHA512 -> keyScheduleR' SHA512
        _ -> error "keyScheduleR"
    open' = case aead_id of
        AES_128_GCM -> openA (Proxy :: Proxy AES128)
        AES_256_GCM -> openA (Proxy :: Proxy AES256)
        ChaCha20Poly1305 -> openA (Proxy :: Proxy ChaCha20Poly1305)
        _ -> error "keyScheduleR"
    ns = case aead_id of
        AES_128_GCM -> let proxy = Proxy :: Proxy AES128 in (nK proxy, nN proxy)
        AES_256_GCM -> let proxy = Proxy :: Proxy AES256 in (nK proxy, nN proxy)
        ChaCha20Poly1305 -> let proxy = Proxy :: Proxy ChaCha20Poly1305 in (nK proxy, nN proxy)
        _ -> error "keyScheduleR"

keyScheduleR'
    :: ( HashAlgorithm h
       , KDF h
       )
    => h
    -> Open
    -> (Int, Int)
    -> Suite
    -> Mode
    -> SharedSecret
    -> Info
    -> PSK
    -> PSK_ID
    -> IO ContextR
keyScheduleR' h open' ns suite mode shared_secret info psk psk_id = do
    seqref <- newIORef 0
    let (key, nonce_base, _, _) = keySchedule h ns mode suite shared_secret info psk psk_id
    return $
        ContextR
            { seqRefR = seqref
            , openR = open' key
            , nonceBaseR = nonce_base
            }

----------------------------------------------------------------

keySchedule
    :: forall h
     . (HashAlgorithm h, KDF h)
    => h
    -> (Int, Int)
    -> Mode
    -> Suite
    -> SharedSecret
    -> Info
    -> PSK
    -> PSK_ID
    -> (ByteString, ByteString, Int, ByteString)
keySchedule h (nk, nn) mode suite shared_secret info psk psk_id =
    (key, base_nonce, 0, exporter_secret)
  where
    psk_id_hash = labeledExtract suite "" "psk_id_hash" psk_id :: PRK h
    info_hash = labeledExtract suite "" "info_hash" info :: PRK h
    key_schedule_context =
        BS.singleton (fromMode mode) <> convert psk_id_hash <> convert info_hash
            :: ByteString

    secret = labeledExtract suite (convert shared_secret) "secret" psk :: PRK h

    key = labeledExpand suite secret "key" key_schedule_context nk
    base_nonce = labeledExpand suite secret "base_nonce" key_schedule_context nn

    exporter_secret = labeledExpand suite secret "exp" key_schedule_context $ hashDigestSize h

----------------------------------------------------------------
