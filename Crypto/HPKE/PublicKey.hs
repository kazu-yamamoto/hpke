module Crypto.HPKE.PublicKey (
    SecretKey,
    DeserialSK (..),
    PublicKey,
    serializePublicKey,
    deserializePublicKey,
)
where

import Crypto.ECC (
    Curve_P256R1,
    Curve_P384R1,
    Curve_P521R1,
    Curve_X25519,
    Curve_X448,
    EllipticCurve (..),
    EllipticCurveBasepointArith (..),
    Point,
    Scalar,
    decodePoint,
    decodeScalar,
 )
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448

import Crypto.HPKE.Types

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Crypto.ECC
-- >>> import Crypto.Hash.Algorithms
-- >>> import Data.ByteString

----------------------------------------------------------------

type PublicKey group = Point group
type SecretKey group = Scalar group

----------------------------------------------------------------

class DeserialSK group where
    deserializeSK
        :: Proxy group -> EncodedSecretKey -> Either HPKEError (SecretKey group)

instance DeserialSK Curve_P256R1 where
    deserializeSK proxy (EncodedSecretKey sk) = case decodeScalar proxy sk of
        CryptoPassed a -> Right a
        CryptoFailed _ -> Left $ DeserializeError "P256"

instance DeserialSK Curve_P384R1 where
    deserializeSK proxy (EncodedSecretKey sk) = case decodeScalar proxy sk of
        CryptoPassed a -> Right a
        CryptoFailed _ -> Left $ DeserializeError "P384"

instance DeserialSK Curve_P521R1 where
    deserializeSK proxy (EncodedSecretKey sk) = case decodeScalar proxy sk of
        CryptoPassed a -> Right a
        CryptoFailed _ -> Left $ DeserializeError "P521"

instance DeserialSK Curve_X25519 where
    deserializeSK _ (EncodedSecretKey sk) = case X25519.secretKey sk of
        CryptoPassed a -> Right a
        CryptoFailed _ -> Left $ DeserializeError "X25519"

instance DeserialSK Curve_X448 where
    deserializeSK _ (EncodedSecretKey sk) = case X448.secretKey sk of
        CryptoPassed a -> Right a
        CryptoFailed _ -> Left $ DeserializeError "X448"

serializePublicKey
    :: EllipticCurve group
    => Proxy group -> PublicKey group -> EncodedPublicKey
serializePublicKey proxy pk = EncodedPublicKey $ encodePoint proxy pk

deserializePublicKey
    :: EllipticCurve group
    => Proxy group -> EncodedPublicKey -> Either HPKEError (PublicKey group)
deserializePublicKey proxy (EncodedPublicKey pkm) =
    case decodePoint proxy pkm of
        CryptoPassed a -> Right a
        CryptoFailed _ -> Left $ DeserializeError "deserializePublicKey"
