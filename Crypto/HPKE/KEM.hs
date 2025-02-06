{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KEM (
    encapGen,
    encapEnv,
    decapEnv,
    DeserialSK (..),
)
where

import Crypto.ECC (
    EllipticCurve (..),
    EllipticCurveDH (..),
    KeyPair (..),
 )
import Crypto.Random (drgNew, withDRG)

import Crypto.HPKE.PublicKey
import Crypto.HPKE.Types

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

{- FOURMOLU_DISABLE -}
data Env curve = Env
    { envSecretKey :: SecretKey curve
    , envPublicKey :: PublicKey curve
    , envProxy     :: Proxy curve
    , envDerive    :: KeyDeriveFunction
    }
{- FOURMOLU_ENABLE -}

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

ecdh'
    :: EllipticCurveDH curve
    => Proxy curve
    -> SecretKey curve
    -> PublicKey curve
    -> a
    -> Either a SharedSecret
ecdh' proxy sk pk err = case ecdh proxy sk pk of
    CryptoPassed a -> Right a
    CryptoFailed _ -> Left err
