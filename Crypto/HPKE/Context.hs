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

import Control.Concurrent.MVar (MVar, modifyMVar, newMVar)
import qualified Control.Exception as E
import Data.ByteArray (xor)
import qualified Data.ByteString as BS
import Data.IORef (IORef, atomicModifyIORef', newIORef)

import Crypto.HPKE.Types

----------------------------------------------------------------

-- | Context for senders.
data ContextS = ContextS
    { seqRefS :: IORef Integer
    , sealS :: Seal
    , nonceBaseS :: Nonce
    , expandS :: Info -> Int -> Either HPKEError Key
    }

-- | Context for receivers.
data ContextR = ContextR
    { seqVarR :: MVar Integer
    , openR :: Open
    , nonceBaseR :: Nonce
    , expandR :: Info -> Int -> Either HPKEError Key
    }

----------------------------------------------------------------

-- | Encryption.
--   This throws 'HPKEError'.
--   Safe to call from multiple threads: each call gets its own nonce.
seal :: ContextS -> AAD -> PlainText -> IO CipherText
seal ContextS{..} aad pt = do
    seqI <- atomicModifyIORef' seqRefS $ \i -> (i + 1, i)
    checkLimit nonceBaseS seqI
    either E.throwIO return $ sealS (computeNonce nonceBaseS seqI) aad pt

-- | Decryption.
--   This throws 'HPKEError'.
--   The sequence number advances only when decryption succeeds.
open
    :: ContextR -> AAD -> CipherText -> IO PlainText
open ContextR{..} aad ct = modifyMVar seqVarR $ \seqI -> do
    checkLimit nonceBaseR seqI
    case openR (computeNonce nonceBaseR seqI) aad ct of
        Left err -> E.throwIO err
        Right pt -> return (seqI + 1, pt)

computeNonce :: Nonce -> Integer -> Nonce
computeNonce nonce_base seqI = seqBS `xor` nonce_base
  where
    seqBS = i2ospOf_ (BS.length nonce_base) seqI :: ByteString

-- RFC 9180 section 5.2: the sequence number must not wrap around.
checkLimit :: Nonce -> Integer -> IO ()
checkLimit nonce_base seqI
    | seqI >= 2 ^ (8 * BS.length nonce_base) - 1 =
        E.throwIO $ MessageLimitReachedError "sequence number overflow"
    | otherwise = return ()

----------------------------------------------------------------

-- | Exporting secret.
--
-- RFC 9180 section 5.3 allows a length of at most @255 * Nh@, where @Nh@ is
-- the output of the KDF's hash; a longer one is 'Left' 'ExportError'.
exportS :: ContextS -> Info -> Int -> Either HPKEError Key
exportS ContextS{..} exporter_context len =
    expandS exporter_context len

-- | Exporting secret.
--
-- RFC 9180 section 5.3 allows a length of at most @255 * Nh@, where @Nh@ is
-- the output of the KDF's hash; a longer one is 'Left' 'ExportError'.
exportR :: ContextR -> Info -> Int -> Either HPKEError Key
exportR ContextR{..} exporter_context len =
    expandR exporter_context len

----------------------------------------------------------------

newContextS
    :: Key
    -> Nonce
    -> (Key -> Seal)
    -> (Info -> Int -> Either HPKEError Key)
    -> IO ContextS
newContextS key nonce_base seal' expand = do
    seqref <- newIORef 0
    return $
        ContextS
            { seqRefS = seqref
            , sealS = seal' key
            , nonceBaseS = nonce_base
            , expandS = expand
            }

----------------------------------------------------------------

newContextR
    :: Key
    -> Nonce
    -> (Key -> Open)
    -> (Info -> Int -> Either HPKEError Key)
    -> IO ContextR
newContextR key nonce_base open' expand = do
    seqvar <- newMVar 0
    return $
        ContextR
            { seqVarR = seqvar
            , openR = open' key
            , nonceBaseR = nonce_base
            , expandR = expand
            }
