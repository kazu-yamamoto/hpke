{-# LANGUAGE RecordWildCards #-}

module Crypto.HPKE.Context (
    -- * Sender
    ContextS,
    newContextS,
    seal,
    exportS,

    -- * Receiver
    ContextR,
    newContextR,
    open,
    exportR,
) where

import Ageha.Cipher.AEAD
import Ageha.KDF.HKDF
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
    , expandS :: Info -> Int -> ByteString
    }

-- | Context for receivers.
data ContextR = ContextR
    { seqRefR :: IORef Integer
    , openR :: Open
    , nonceBaseR :: Nonce
    , expandR :: Info -> Int -> ByteString
    }

----------------------------------------------------------------

-- | Encryption.
--   This throws 'HPKEError'.
seal :: ContextS -> AAD -> PlainText -> IO CipherText
seal ContextS{..} aad pt = do
    seqI <- readIORef seqRefS
    let nonce' = getNonce nonceBaseS
        len = BS.length nonce'
        seqBS = i2ospOf_ len seqI :: ByteString
        nonce = Nonce (seqBS `xor` nonce')
        seqI' = seqI + 1
    writeIORef seqRefS seqI'
    sealS nonce aad pt

-- | Decryption.
--   This throws 'HPKEError'.
open
    :: ContextR -> AAD -> CipherText -> IO PlainText
open ContextR{..} aad ct = do
    seqI <- readIORef seqRefR
    let nonce' = getNonce nonceBaseR
        len = BS.length $ getNonce nonceBaseR
        seqBS = i2ospOf_ len seqI :: ByteString
        nonce = Nonce (seqBS `xor` nonce')
    pt <- openR nonce aad ct
    let seqI' = seqI + 1
    writeIORef seqRefR seqI'
    return pt

----------------------------------------------------------------

-- | Exporting secret.
exportS :: ContextS -> Info -> Int -> ByteString
exportS ContextS{..} exporter_context len =
    expandS exporter_context len

-- | Exporting secret.
exportR :: ContextR -> Info -> Int -> ByteString
exportR ContextR{..} exporter_context len =
    expandR exporter_context len

----------------------------------------------------------------

newContextS
    :: Key
    -> Nonce
    -> AEADName
    -> (Info -> Int -> ByteString)
    -> IO ContextS
newContextS key nonce_base an expand = do
    seqref <- newIORef 0
    enc <- aeadInitEncrypt an key
    return $
        ContextS
            { seqRefS = seqref
            , sealS = aeadEncrypt enc
            , nonceBaseS = nonce_base
            , expandS = expand
            }

----------------------------------------------------------------

newContextR
    :: Key
    -> Nonce
    -> AEADName
    -> (Info -> Int -> ByteString)
    -> IO ContextR
newContextR key nonce_base an expand = do
    seqref <- newIORef 0
    dec <- aeadInitDecrypt an key
    return $
        ContextR
            { seqRefR = seqref
            , openR = aeadDecrypt dec
            , nonceBaseR = nonce_base
            , expandR = expand
            }
