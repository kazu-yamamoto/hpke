{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.HPKE.KEM (
    encapGen,
    encapEnv,
    decapEnv,
    DeserialSK (..),
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
    EllipticCurveDH (..),
    KeyPair (..),
    Point,
    Scalar,
    decodePoint,
    decodeScalar,
 )
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import Crypto.Random (drgNew, withDRG)

import Crypto.HPKE.Types

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Crypto.ECC
-- >>> import Crypto.Hash.Algorithms
-- >>> import Data.ByteString

----------------------------------------------------------------

type PublicKey curve = Point curve
type SecretKey curve = Scalar curve

{- FOURMOLU_DISABLE -}
data Env curve = Env
    { envSecretKey :: SecretKey curve
    , envPublicKey :: PublicKey curve
    , envProxy     :: Proxy curve
    , envDerive    :: KeyDeriveFunction
    }
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

encap
    :: (EllipticCurve curve, EllipticCurveDH curve)
    => Env curve
    -> Encap
encap Env{..} enc0@(EncodedPublicKey pkRm) = do
    pkR <- deserializePublicKey envProxy enc0
    dh <- ecdh' envProxy envSecretKey pkR $ EncapError "encap"
    let enc@(EncodedPublicKey pkEm) = serializePublicKey envProxy envPublicKey
        kem_context = pkEm <> pkRm
        shared_secret = SharedSecret $ convert $ envDerive dh kem_context
    return (shared_secret, enc)

encapGen
    :: (EllipticCurve curve, EllipticCurveDH curve, DeserialSK curve)
    => Proxy curve
    -> KeyDeriveFunction
    -> IO Encap
encapGen proxy derive = do
    env <- genEnv proxy derive
    return $ encap env

encapEnv
    :: (EllipticCurve curve, EllipticCurveDH curve, DeserialSK curve)
    => Proxy curve
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Encap
encapEnv proxy derive skRm pkRm enc = do
    env <- newEnvDeserialize proxy derive skRm pkRm
    encap env enc

----------------------------------------------------------------

decap
    :: (EllipticCurve curve, EllipticCurveDH curve)
    => Env curve
    -> Decap
decap Env{..} enc@(EncodedPublicKey pkEm) = do
    pkE <- deserializePublicKey envProxy enc
    dh <- ecdh' envProxy envSecretKey pkE $ DecapError "decap"
    let EncodedPublicKey pkRm = serializePublicKey envProxy envPublicKey
        kem_context = pkEm <> pkRm
        shared_secret = SharedSecret $ convert $ envDerive dh kem_context
    return shared_secret

decapEnv
    :: (EllipticCurve curve, EllipticCurveDH curve, DeserialSK curve)
    => Proxy curve
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Decap
decapEnv proxy derive skRm pkRm enc = do
    env <- newEnvDeserialize proxy derive skRm pkRm
    decap env enc

----------------------------------------------------------------

newEnv
    :: forall curve
     . EllipticCurve curve
    => KeyDeriveFunction
    -> SecretKey curve
    -> PublicKey curve
    -> Env curve
newEnv derive skR pkR =
    Env
        { envSecretKey = skR
        , envPublicKey = pkR
        , envProxy = proxy
        , envDerive = derive
        }
  where
    proxy = Proxy :: Proxy curve

----------------------------------------------------------------

genEnv
    :: EllipticCurve curve
    => Proxy curve -> KeyDeriveFunction -> IO (Env curve)
genEnv proxy derive = do
    gen <- drgNew
    let (KeyPair pk sk, _) = withDRG gen $ curveGenerateKeyPair proxy
    return $ newEnv derive sk pk

----------------------------------------------------------------

newEnvDeserialize
    :: (EllipticCurve curve, DeserialSK curve)
    => Proxy curve
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Either HpkeError (Env curve)
newEnvDeserialize proxy derive skRm pkRm = do
    skR <- deserializeSK proxy skRm
    pkR <- deserializePublicKey proxy pkRm
    return $ newEnv derive skR pkR

----------------------------------------------------------------

class DeserialSK curve where
    deserializeSK
        :: Proxy curve -> EncodedSecretKey -> Either HpkeError (SecretKey curve)

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

deserializePublicKey
    :: EllipticCurve curve
    => Proxy curve -> EncodedPublicKey -> Either HpkeError (PublicKey curve)
deserializePublicKey proxy (EncodedPublicKey pkm) =
    case decodePoint proxy pkm of
        CryptoPassed a -> Right a
        CryptoFailed _ -> Left $ DeserializeError "deserializePublicKey"

serializePublicKey
    :: EllipticCurve curve
    => Proxy curve -> PublicKey curve -> EncodedPublicKey
serializePublicKey proxy pk = EncodedPublicKey $ encodePoint proxy pk

----------------------------------------------------------------

ecdh'
    :: EllipticCurveDH curve
    => Proxy curve
    -> Scalar curve
    -> Point curve
    -> a
    -> Either a SharedSecret
ecdh' proxy sk pk err = case ecdh proxy sk pk of
    CryptoPassed a -> Right a
    CryptoFailed _ -> Left err
