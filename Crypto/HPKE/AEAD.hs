{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeSynonymInstances #-}

module Crypto.HPKE.AEAD (
    AEAD_ID (AES_128_GCM, AES_256_GCM, ChaCha20Poly1305, ..),
    Aead (..),
    AES128,
    AES256,
    ChaCha20Poly1305,
) where

import Crypto.Cipher.AES (AES128, AES256)
import Crypto.Cipher.ChaChaPoly1305 (ChaCha20Poly1305)
import qualified Crypto.Cipher.ChaChaPoly1305 as CCP
import Crypto.Cipher.Types (AEAD (..), AuthTag (..))
import qualified Crypto.Cipher.Types as Cipher
import Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteString as BS
import Data.Tuple (swap)
import Data.Word
import Text.Printf

import Crypto.HPKE.Types

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Data.ByteString

----------------------------------------------------------------

-- | ID for authenticated encryption with additional data
newtype AEAD_ID = AEAD_ID {fromAEAD_ID :: Word16} deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern AES_128_GCM      :: AEAD_ID
pattern AES_128_GCM       = AEAD_ID 0x0001
pattern AES_256_GCM      :: AEAD_ID
pattern AES_256_GCM       = AEAD_ID 0x0002
pattern ChaCha20Poly1305 :: AEAD_ID
pattern ChaCha20Poly1305  = AEAD_ID 0x0003

instance Show AEAD_ID where
    show AES_128_GCM      = "AES_128_GCM"
    show AES_256_GCM      = "AES_256_GCM"
    show ChaCha20Poly1305 = "ChaCha20Poly1305"
    show (AEAD_ID n)      = "AEAD_ID 0x" ++ printf "%04x" n
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

class Aead a where
    sealA :: Proxy a -> Key -> Seal
    openA :: Proxy a -> Key -> Open
    nK :: Proxy a -> Int
    nN :: Proxy a -> Int
    nT :: Proxy a -> Int

mkSealA :: AeadEncrypt -> p -> Key -> Seal
mkSealA enc _ key nonce aad plain = cipher <> convert tag
  where
    (cipher, AuthTag tag) = enc key nonce aad plain

mkOpenA :: AeadDecrypt -> Int -> p -> Key -> Open
mkOpenA dec len _ key nonce aad cipher
    | tag == convert tag' = Right plain
    | otherwise = Left OpenError
  where
    brkpt = BS.length cipher - len
    (cipher', tag') = BS.splitAt brkpt cipher
    (plain, AuthTag tag) = dec key nonce aad cipher'

----------------------------------------------------------------

type AeadEncrypt =
    forall k n a t
     . ( ByteArray k
       , ByteArrayAccess n
       , ByteArrayAccess a
       , ByteArray t
       )
    => k -> n -> a -> t -> (t, AuthTag)

type AeadDecrypt =
    forall k n a t
     . ( ByteArray k
       , ByteArrayAccess n
       , ByteArrayAccess a
       , ByteArray t
       )
    => k -> n -> a -> t -> (t, AuthTag)

----------------------------------------------------------------

-- | From RFC 9180 A.1
--
-- >>> let key = "\x45\x31\x68\x5d\x41\xd6\x5f\x03\xdc\x48\xf6\xb8\x30\x2c\x05\xb0" :: ByteString
-- >>> let nonce = "\x56\xd8\x90\xe5\xac\xca\xaf\x01\x1c\xff\x4b\x7d" :: ByteString
-- >>> let aad = "\x43\x6f\x75\x6e\x74\x2d\x30" :: ByteString
-- >>> let plain = "The quick brown fox jumps over the very lazy dog." :: ByteString
-- >>> let proxy = Proxy :: Proxy AES128
-- >>> openA proxy key nonce aad $ sealA proxy key nonce aad plain
-- Right "The quick brown fox jumps over the very lazy dog."
instance Aead AES128 where
    sealA = mkSealA encryptAes128gcm
    openA = mkOpenA decryptAes128gcm aes128tagLength
    nK = const 16
    nN = const 12
    nT = const 16

encryptAes128gcm :: AeadEncrypt
encryptAes128gcm key nonce aad plain =
    simpleEncrypt st1 aad plain aes128tagLength
  where
    st0 = noFail (Cipher.cipherInit key) :: AES128
    st1 = noFail $ Cipher.aeadInit Cipher.AEAD_GCM st0 nonce

decryptAes128gcm :: AeadDecrypt
decryptAes128gcm key nonce aad cipher =
    simpleDecrypt st1 aad cipher aes128tagLength
  where
    st0 = noFail (Cipher.cipherInit key) :: AES128
    st1 = noFail $ Cipher.aeadInit Cipher.AEAD_GCM st0 nonce

aes128tagLength :: Int
aes128tagLength = 16

----------------------------------------------------------------

-- | From RFC 9180 A.6
--
-- >>> let key = "\x75\x1e\x34\x6c\xe8\xf0\xdd\xb2\x30\x5c\x8a\x2a\x85\xc7\x0d\x5c\xf5\x59\xc5\x30\x93\x65\x6b\xe6\x36\xb9\x40\x6d\x4d\x7d\x1b\x70" :: ByteString
-- >>> let nonce = "\x55\xff\x7a\x7d\x73\x9c\x69\xf4\x4b\x25\x44\x7b" :: ByteString
-- >>> let aad = "\x43\x6f\x75\x6e\x74\x2d\x30" :: ByteString
-- >>> let plain = "The quick brown fox jumps over the very lazy dog." :: ByteString
-- >>> let proxy = Proxy :: Proxy AES256
-- >>> openA proxy key nonce aad $ sealA proxy key nonce aad plain
-- Right "The quick brown fox jumps over the very lazy dog."
instance Aead AES256 where
    sealA = mkSealA encryptAes256gcm
    openA = mkOpenA decryptAes256gcm aes256tagLength
    nK = const 32
    nN = const 12
    nT = const 16

encryptAes256gcm :: AeadEncrypt
encryptAes256gcm key nonce aad plain =
    simpleEncrypt st1 aad plain aes256tagLength
  where
    st0 = noFail (Cipher.cipherInit key) :: AES256
    st1 = noFail $ Cipher.aeadInit Cipher.AEAD_GCM st0 nonce

decryptAes256gcm :: AeadDecrypt
decryptAes256gcm key nonce aad cipher =
    simpleDecrypt st1 aad cipher aes256tagLength
  where
    st0 = noFail (Cipher.cipherInit key) :: AES256
    st1 = noFail $ Cipher.aeadInit Cipher.AEAD_GCM st0 nonce

aes256tagLength :: Int
aes256tagLength = 16

----------------------------------------------------------------

-- | From RFC 9180 A.5
--
-- >>> let key = "\xa8\xf4\x54\x90\xa9\x2a\x3b\x04\xd1\xdb\xf6\xcf\x2c\x39\x39\xad\x8b\xfc\x9b\xfc\xb9\x7c\x04\xbf\xfe\x11\x67\x30\xc9\xdf\xe3\xfc" :: ByteString
-- >>> let nonce = "\x72\x6b\x43\x90\xed\x22\x09\x80\x9f\x58\xc6\x93" :: ByteString
-- >>> let aad = "\x43\x6f\x75\x6e\x74\x2d\x30" :: ByteString
-- >>> let plain = "The quick brown fox jumps over the very lazy dog." :: ByteString
-- >>> let proxy = Proxy :: Proxy ChaCha20Poly1305
-- >>> openA proxy key nonce aad $ sealA proxy key nonce aad plain
-- Right "The quick brown fox jumps over the very lazy dog."
instance Aead CCP.ChaCha20Poly1305 where
    sealA = mkSealA encryptChacha20poly1305
    openA = mkOpenA decryptChacha20poly1305 chacha20poly1305tagLength
    nK = const 32
    nN = const 12
    nT = const 16

encryptChacha20poly1305 :: AeadEncrypt
encryptChacha20poly1305 key nonce aad plain =
    simpleEncrypt st aad plain chacha20poly1305tagLength
  where
    st = CCP.aeadChacha20poly1305Init key nonce

decryptChacha20poly1305 :: AeadDecrypt
decryptChacha20poly1305 key nonce aad cipher =
    simpleDecrypt st aad cipher chacha20poly1305tagLength
  where
    st = CCP.aeadChacha20poly1305Init key nonce

chacha20poly1305tagLength :: Int
chacha20poly1305tagLength = 16

----------------------------------------------------------------

simpleEncrypt
    :: (ByteArrayAccess a, ByteArray t)
    => AEAD cipher -> a -> t -> Int -> (t, AuthTag)
simpleEncrypt st aad plain taglen =
    swap $ Cipher.aeadSimpleEncrypt st aad plain taglen

simpleDecrypt
    :: (ByteArrayAccess a, ByteArray t)
    => AEAD cipher -> a -> t -> Int -> (t, AuthTag)
simpleDecrypt st aad cipher taglen = (plain, tag)
  where
    st2 = Cipher.aeadAppendHeader st aad
    (plain, st3) = Cipher.aeadDecrypt st2 cipher
    tag = Cipher.aeadFinalize st3 taglen
