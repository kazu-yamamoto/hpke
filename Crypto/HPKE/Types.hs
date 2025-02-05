{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeSynonymInstances #-}

module Crypto.HPKE.Types (
    HpkeError (..),
    Salt,
    IKM,
    Key,
    Suite,
    Label,
    KeyDeriveFunction,
    Nonce,
    AAD,
    PlainText,
    CipherText,
    Seal,
    Open,
    EncodedPublicKey (..),
    EncodedSecretKey (..),
    Info,
    PSK,
    PSK_ID,
    Encap,
    Decap,
    -- rexport
    CryptoFailable (..),
    SharedSecret (..),
    hashDigestSize,
    i2ospOf_,
    convert,
    Proxy (..),
    ByteString,
    Word8,
    Word16,
    printf,
    lookupE,
) where

import Control.Exception (Exception)
import Crypto.ECC (SharedSecret (..))
import Crypto.Error (CryptoFailable (..))
import Crypto.Hash.IO (hashDigestSize)
import Crypto.Number.Serialize (i2ospOf_)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Data.Proxy (Proxy (..))
import Data.String
import Data.Word (Word16, Word8)
import Text.Printf (printf)

----------------------------------------------------------------

data HpkeError
    = ValidationError String
    | DeserializeError String
    | EncapError String
    | DecapError String
    | SealError String -- original
    | OpenError String
    | MessageLimitReachedError String
    | DeriveKeyPairError String
    | Unsupported String -- original
    deriving (Eq, Show)

instance Exception HpkeError

----------------------------------------------------------------

type Salt = ByteString
type IKM = ByteString -- Input Keying Material
type Key = ByteString
type Suite = ByteString
type Label = ByteString
type KeyDeriveFunction = SharedSecret -> ByteString -> Key

----------------------------------------------------------------

type Nonce = ByteString

-- | Additional authenticated data for AEAD.
type AAD = ByteString

-- | Plain text.
type PlainText = ByteString

-- | Cipher text (including a authentication tag)
type CipherText = ByteString

type Seal = Nonce -> AAD -> PlainText -> Either HpkeError CipherText
type Open = Nonce -> AAD -> CipherText -> Either HpkeError PlainText

----------------------------------------------------------------

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

----------------------------------------------------------------

type Encap =
    EncodedPublicKey -> Either HpkeError (SharedSecret, EncodedPublicKey)
type Decap = EncodedPublicKey -> Either HpkeError SharedSecret

----------------------------------------------------------------

-- | Information string.
type Info = ByteString

-- | Pre-shared key.
type PSK = ByteString

-- | ID for pre-shared key.
type PSK_ID = ByteString

----------------------------------------------------------------

lookupE :: (Eq k, Show k) => k -> [(k, v)] -> Either HpkeError v
lookupE k table = case lookup k table of
    Nothing -> Left $ Unsupported $ show k
    Just v -> Right v
