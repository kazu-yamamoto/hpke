{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KeySchedule (
    -- * Types
    Mode (..),

    -- * Sender
    ContextS,
    newContextS,
    seal,

    -- * Receiver
    ContextR,
    newContextR,
    open,

    -- * Key schedule
    keySchedule,
) where

import qualified Control.Exception as E
import Data.ByteArray (xor)
import qualified Data.ByteString as BS
import Data.IORef (IORef, newIORef, readIORef, writeIORef)

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
--   This throws 'HpkeError'.
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
--   This throws 'HpkeError'.
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

newContextS
    :: (ByteString, ByteString, Int, ByteString)
    -> (Key -> Seal)
    -> IO ContextS
newContextS (key, nonce_base, _, _) seal' = do
    seqref <- newIORef 0
    return $
        ContextS
            { seqRefS = seqref
            , sealS = seal' key
            , nonceBaseS = nonce_base
            }

----------------------------------------------------------------

newContextR
    :: (ByteString, ByteString, Int, ByteString)
    -> (Key -> Open)
    -> IO ContextR
newContextR (key, nonce_base, _, _) open' = do
    seqref <- newIORef 0
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
    -> Suite
    -> Int
    -> Int
    -> Mode
    -> Info
    -> PSK
    -> PSK_ID
    -> SharedSecret
    -> (ByteString, ByteString, Int, ByteString)
keySchedule h suite nk nn mode info psk psk_id shared_secret =
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
