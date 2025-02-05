{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Crypto.HPKE.Types (
    HpkeError (..),
    Salt,
    IKM,
    Key,
    Suite,
    Label,
    KeyDeriveFunction,
    KeyDeriveFunction',
    Nonce,
    AssociatedData,
    PlainText,
    CipherText,
    SealK,
    Seal,
    OpenK,
    Open,
    PublicKey,
    SecretKey,
    EncodedPublicKey (..),
    EncodedSecretKey (..),
    Info,
    PSK,
    PSK_ID,
    noFail,
    -- rexport
    SharedSecret (..),
    hashDigestSize,
    i2ospOf_,
    convert,
    Proxy (..),
    ByteString,
) where

import Crypto.ECC (Point, Scalar, SharedSecret (..))
import Crypto.Error
import Crypto.Hash.IO (hashDigestSize)
import Crypto.Number.Serialize (i2ospOf_)
import qualified Crypto.PubKey.Curve25519 as X25519
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Data.Proxy (Proxy (..))
import Data.String

----------------------------------------------------------------

data HpkeError
    = ValidationError
    | DeserializeError
    | EncapError
    | DecapError
    | OpenError
    | MessageLimitReachedError
    | DeriveKeyPairError
    deriving (Eq, Show)

----------------------------------------------------------------

type Salt = ByteString
type IKM = ByteString -- Input Keying Material
type Key = ByteString
type Suite = ByteString
type Label = ByteString
type KeyDeriveFunction = Suite -> SharedSecret -> ByteString -> Key
type KeyDeriveFunction' = SharedSecret -> ByteString -> Key

----------------------------------------------------------------

type Nonce = ByteString

-- | Associated data for AEAD.
type AssociatedData = ByteString

-- | Plain text.
type PlainText = ByteString

-- | Cipher text (including a authentication tag)
type CipherText = ByteString

type SealK = Nonce -> AssociatedData -> PlainText -> CipherText
type Seal = Key -> SealK
type OpenK = Nonce -> AssociatedData -> CipherText -> Either HpkeError PlainText
type Open = Key -> OpenK

----------------------------------------------------------------

noFail :: CryptoFailable a -> a
noFail = throwCryptoError

----------------------------------------------------------------

type PublicKey curve = Point curve
type SecretKey curve = Scalar curve

-- | Encoded public key.
newtype EncodedPublicKey = EncodedPublicKey ByteString deriving (Eq)

-- | Encoded secret key.
newtype EncodedSecretKey = EncodedSecretKey ByteString deriving (Eq)

instance Show EncodedPublicKey where
    show (EncodedPublicKey pk) = showBS16 pk

instance Show EncodedSecretKey where
    show (EncodedSecretKey pk) = showBS16 pk

instance IsString EncodedPublicKey where
    fromString = EncodedPublicKey . fromString

instance IsString EncodedSecretKey where
    fromString = EncodedSecretKey . fromString

showBS16 :: ByteString -> String
showBS16 bs = "\"" <> s16 <> "\""
  where
    s16 = C8.unpack $ B16.encode bs

instance IsString X25519.PublicKey where
    fromString s = throwCryptoError $ X25519.publicKey bs
      where
        bs = fromString s :: ByteString

instance IsString X25519.SecretKey where
    fromString s = throwCryptoError $ X25519.secretKey bs
      where
        bs = fromString s :: ByteString

instance Show SharedSecret where
    show (SharedSecret sb) = showBS16 $ convert sb

----------------------------------------------------------------

-- | Information string.
type Info = ByteString

-- | Pre-shared key.
type PSK = ByteString

-- | ID for pre-shared key.
type PSK_ID = ByteString
