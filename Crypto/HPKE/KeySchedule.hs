{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KeySchedule (
    -- * Types
    Mode (..),
    KEM_ID (..),
    KDF_ID (..),
    AEAD_ID (..),

    -- * Sender
    ContextS,
    keyScheduleS,
    seal,

    -- * Receiver
    ContextR,
    keyScheduleR,
    open,
) where

import qualified Control.Exception as E
import Data.ByteArray (xor)
import qualified Data.ByteString as BS
import Data.IORef (IORef, newIORef, readIORef, writeIORef)

import Crypto.HPKE.AEAD
import Crypto.HPKE.KDF
import Crypto.HPKE.KEM
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
    , sealS :: Seal
    , nonceBaseS :: Nonce
    }

-- | Context for receivers.
data ContextR = ContextR
    { seqRefR :: IORef Integer
    , openR :: Open
    , nonceBaseR :: Nonce
    }

----------------------------------------------------------------

-- | Encryption.
seal :: ContextS -> AAD -> PlainText -> IO CipherText
seal ContextS{..} aad pt = do
    seqI <- readIORef seqRefS
    let len = BS.length nonceBaseS
        seqBS = i2ospOf_ len seqI :: ByteString
        nonce = seqBS `xor` nonceBaseS
        ect = sealS nonce aad pt
        seqI' = seqI + 1
    writeIORef seqRefS seqI'
    case ect of
        Right ct -> return ct
        Left err -> E.throwIO err

-- | Decryption.
open
    :: ContextR -> AAD -> CipherText -> IO PlainText
open ContextR{..} aad ct = do
    seqI <- readIORef seqRefR
    let len = BS.length nonceBaseR
        seqBS = i2ospOf_ len seqI :: ByteString
        nonce = seqBS `xor` nonceBaseR
        ept = openR nonce aad ct
    case ept of
        Left err -> E.throwIO err
        Right pt -> do
            let seqI' = seqI + 1
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
keyScheduleS kem_id kdf_id aead_id mode ss info psk psk_id = case ex of
    Left err -> E.throwIO err
    Right (ks, (seal', nk, nn)) -> do
        seqref <- newIORef 0
        let (key, nonce_base, _, _) = ks nk nn mode suite_id ss info psk psk_id
        return $
            ContextS
                { seqRefS = seqref
                , sealS = seal' key
                , nonceBaseS = nonce_base
                }
  where
    suite_id = suiteHPKE kem_id kdf_id aead_id
    eks = case lookupE kdf_id defaultKdfMap of
        Right (KDFHash h) -> Right $ keySchedule h
        Left err -> Left err
    eaead = case lookupE aead_id defaultCipherMap of
        Right (AeadCipher aead) -> Right (sealA aead, nK aead, nN aead)
        Left err -> Left err
    ex = do
        ks <- eks
        aead <- eaead
        return (ks, aead)

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
keyScheduleR kem_id kdf_id aead_id mode ss info psk psk_id = case ex of
    Left err -> E.throwIO err
    Right (ks, (open', nk, nn)) -> do
        seqref <- newIORef 0
        let (key, nonce_base, _, _) = ks nk nn mode suite_id ss info psk psk_id
        return $
            ContextR
                { seqRefR = seqref
                , openR = open' key
                , nonceBaseR = nonce_base
                }
  where
    suite_id = suiteHPKE kem_id kdf_id aead_id
    eks = case lookupE kdf_id defaultKdfMap of
        Right (KDFHash h) -> Right $ keySchedule h
        Left err -> Left err
    eaead = case lookupE aead_id defaultCipherMap of
        Right (AeadCipher aead) -> Right (openA aead, nK aead, nN aead)
        Left err -> Left err
    ex = do
        ks <- eks
        aead <- eaead
        return (ks, aead)

----------------------------------------------------------------

keySchedule
    :: forall h
     . (HashAlgorithm h, KDF h)
    => h
    -> Int
    -> Int
    -> Mode
    -> Suite
    -> SharedSecret
    -> Info
    -> PSK
    -> PSK_ID
    -> (ByteString, ByteString, Int, ByteString)
keySchedule h nk nn mode suite shared_secret info psk psk_id =
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

suiteHPKE :: KEM_ID -> KDF_ID -> AEAD_ID -> Suite
suiteHPKE kem_id hkdf_id aead_id = "HPKE" <> i0 <> i1 <> i2
  where
    i0 = i2ospOf_ 2 $ fromIntegral $ fromKEM_ID kem_id
    i1 = i2ospOf_ 2 $ fromIntegral $ fromKDF_ID hkdf_id
    i2 = i2ospOf_ 2 $ fromIntegral $ fromAEAD_ID aead_id
