{-# LANGUAGE RecordWildCards #-}

module Crypto.HPKE.Context (
    -- * Sender
    ContextS,
    newContextS,
    seal,

    -- * Receiver
    ContextR,
    newContextR,
    open,
) where

import qualified Control.Exception as E
import Data.ByteArray (xor)
import qualified Data.ByteString as BS
import Data.IORef (IORef, newIORef, readIORef, writeIORef)

import Crypto.HPKE.Types

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
--   This throws 'HPKEError'.
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
--   This throws 'HPKEError'.
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
