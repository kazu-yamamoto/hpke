{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.HPKE.KEM (
    encapGen,
    encapKEM,
    decapKEM,
    KEM_ID (
        DHKEM_P256_HKDF_SHA256,
        DHKEM_P384_HKDF_SHA384,
        DHKEM_P512_HKDF_SHA512,
        DHKEM_X25519_HKDF_SHA256,
        DHKEM_X448_HKDF_SHA512,
        ..
    ),
    defaultKemMap,
)
where

import qualified Control.Exception as E
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

import Crypto.HPKE.KDF
import Crypto.HPKE.Types

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Crypto.ECC
-- >>> import Crypto.Hash.Algorithms
-- >>> import Data.ByteString

----------------------------------------------------------------

-- | ID for key encapsulation mechanism.
newtype KEM_ID = KEM_ID {fromKEM_ID :: Word16} deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern DHKEM_P256_HKDF_SHA256   :: KEM_ID
pattern DHKEM_P256_HKDF_SHA256    = KEM_ID 0x0010
pattern DHKEM_P384_HKDF_SHA384   :: KEM_ID
pattern DHKEM_P384_HKDF_SHA384    = KEM_ID 0x0011
pattern DHKEM_P512_HKDF_SHA512   :: KEM_ID
pattern DHKEM_P512_HKDF_SHA512    = KEM_ID 0x0012
pattern DHKEM_X25519_HKDF_SHA256 :: KEM_ID
pattern DHKEM_X25519_HKDF_SHA256  = KEM_ID 0x0020
pattern DHKEM_X448_HKDF_SHA512   :: KEM_ID
pattern DHKEM_X448_HKDF_SHA512    = KEM_ID 0x0021

instance Show KEM_ID where
    show DHKEM_P256_HKDF_SHA256   = "DHKEM(P-256, HKDF-SHA256)"
    show DHKEM_P384_HKDF_SHA384   = "DHKEM(P-384, HKDF-SHA384)"
    show DHKEM_P512_HKDF_SHA512   = "DHKEM(P-521, HKDF-SHA512)"
    show DHKEM_X25519_HKDF_SHA256 = "DHKEM(X25519, HKDF-SHA256)"
    show DHKEM_X448_HKDF_SHA512   = "DHKEM(X448, HKDF-SHA512)"
    show (KEM_ID n)               = "DHKEM_ID 0x" ++ printf "%04x" n
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
p256   :: Proxy Curve_P256R1
p256    = Proxy :: Proxy Curve_P256R1
p384   :: Proxy Curve_P384R1
p384    = Proxy :: Proxy Curve_P384R1
p521   :: Proxy Curve_P521R1
p521    = Proxy :: Proxy Curve_P521R1
x25519 :: Proxy Curve_X25519
x25519  = Proxy :: Proxy Curve_X25519
x448   :: Proxy Curve_X448
x448    = Proxy :: Proxy Curve_X448

data KEMGroup
    = forall c. (EllipticCurve c, EllipticCurveDH c, DeserialSK c) => KEMGroup (Proxy c)

defaultKemMap :: [(KEM_ID, (KEMGroup, KDFHash))]
defaultKemMap =
    [ (DHKEM_P256_HKDF_SHA256,   (KEMGroup p256,   KDFHash SHA256))
    , (DHKEM_P384_HKDF_SHA384,   (KEMGroup p384,   KDFHash SHA384))
    , (DHKEM_P512_HKDF_SHA512,   (KEMGroup p521,   KDFHash SHA512))
    , (DHKEM_X25519_HKDF_SHA256, (KEMGroup x25519, KDFHash SHA256))
    , (DHKEM_X448_HKDF_SHA512,   (KEMGroup x448,   KDFHash SHA512))
    ]
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

type PublicKey curve = Point curve
type SecretKey curve = Scalar curve

data Env curve = Env
    { envSecretKey :: SecretKey curve
    , envPublicKey :: PublicKey curve
    , envProxy :: Proxy curve
    , envDerive :: KeyDeriveFunction
    }

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
  where

encapGen
    :: KEM_ID
    -> IO Encap
encapGen kem_id = case lookupE kem_id defaultKemMap of
    Left err -> E.throwIO err
    Right (KEMGroup curve, _) -> do
        env <- genEnv curve kem_id
        return $ encap env

encapKEM
    :: KEM_ID
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Encap
encapKEM kem_id skRm pkRm enc = do
    (KEMGroup curve, _) <- lookupE kem_id defaultKemMap
    env <- newEnvP curve kem_id skRm pkRm
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

decapKEM
    :: KEM_ID
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Decap
decapKEM kem_id skRm pkRm enc = do
    (KEMGroup curve, _) <- lookupE kem_id defaultKemMap
    env <- newEnvP curve kem_id skRm pkRm
    decap env enc

----------------------------------------------------------------

newEnv
    :: forall curve
     . EllipticCurve curve
    => KEM_ID -> SecretKey curve -> PublicKey curve -> Either HpkeError (Env curve)
newEnv kem_id skR pkR = do
    (_, KDFHash h) <- lookupE kem_id defaultKemMap
    return $
        Env
            { envSecretKey = skR
            , envPublicKey = pkR
            , envProxy = proxy
            , envDerive = extractAndExpandH h suite
            }
  where
    proxy = Proxy :: Proxy curve
    suite = suiteKEM kem_id

genEnv
    :: EllipticCurve curve
    => Proxy curve -> KEM_ID -> IO (Env curve)
genEnv proxy kem_id = do
    gen <- drgNew
    let (KeyPair pk sk, _) = withDRG gen $ curveGenerateKeyPair proxy
    case newEnv kem_id sk pk of
        Right env -> return env
        Left err -> E.throwIO err

----------------------------------------------------------------

newEnvP
    :: (EllipticCurve curve, DeserialSK curve)
    => Proxy curve
    -> KEM_ID
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Either HpkeError (Env curve)
newEnvP proxy kem_id skRm pkRm = do
    skR <- deserializeSK proxy skRm
    pkR <- deserializePublicKey proxy pkRm
    newEnv kem_id skR pkR

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

suiteKEM :: KEM_ID -> Suite
suiteKEM kem_id = "KEM" <> i
  where
    i = i2ospOf_ 2 $ fromIntegral $ fromKEM_ID kem_id
