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
    :: (EllipticCurve group, EllipticCurveDH group)
    => Env group
    -> Encap
encap Env{..} enc0@(EncodedPublicKey pkRm) = do
    pkR <- deserializePublicKey envProxy enc0
    dh <- ecdh' envProxy envSecretKey pkR $ EncapError "encap"
    let enc@(EncodedPublicKey pkEm) = serializePublicKey envProxy envPublicKey
        kem_context = pkEm <> pkRm
        shared_secret = SharedSecret $ convert $ envDerive dh kem_context
    return (shared_secret, enc)

encapGen
    :: (EllipticCurve group, EllipticCurveDH group, DeserialSK group)
    => Proxy group
    -> KeyDeriveFunction
    -> IO Encap
encapGen proxy derive = do
    env <- genEnv proxy derive
    return $ encap env

encapEnv
    :: (EllipticCurve group, EllipticCurveDH group, DeserialSK group)
    => Proxy group
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Encap
encapEnv proxy derive skRm pkRm enc = do
    env <- newEnvDeserialize proxy derive skRm pkRm
    encap env enc

----------------------------------------------------------------

decap
    :: (EllipticCurve group, EllipticCurveDH group)
    => Env group
    -> Decap
decap Env{..} enc@(EncodedPublicKey pkEm) = do
    pkE <- deserializePublicKey envProxy enc
    dh <- ecdh' envProxy envSecretKey pkE $ DecapError "decap"
    let EncodedPublicKey pkRm = serializePublicKey envProxy envPublicKey
        kem_context = pkEm <> pkRm
        shared_secret = SharedSecret $ convert $ envDerive dh kem_context
    return shared_secret

decapEnv
    :: (EllipticCurve group, EllipticCurveDH group, DeserialSK group)
    => Proxy group
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Decap
decapEnv proxy derive skRm pkRm enc = do
    env <- newEnvDeserialize proxy derive skRm pkRm
    decap env enc

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
data Env group = Env
    { envSecretKey :: SecretKey group
    , envPublicKey :: PublicKey group
    , envProxy     :: Proxy group
    , envDerive    :: KeyDeriveFunction
    }
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

newEnv
    :: forall group
     . EllipticCurve group
    => KeyDeriveFunction
    -> SecretKey group
    -> PublicKey group
    -> Env group
newEnv derive skR pkR =
    Env
        { envSecretKey = skR
        , envPublicKey = pkR
        , envProxy = proxy
        , envDerive = derive
        }
  where
    proxy = Proxy :: Proxy group

----------------------------------------------------------------

genEnv
    :: EllipticCurve group
    => Proxy group -> KeyDeriveFunction -> IO (Env group)
genEnv proxy derive = do
    gen <- drgNew
    let (KeyPair pk sk, _) = withDRG gen $ curveGenerateKeyPair proxy
    return $ newEnv derive sk pk

----------------------------------------------------------------

newEnvDeserialize
    :: (EllipticCurve group, DeserialSK group)
    => Proxy group
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Either HPKEError (Env group)
newEnvDeserialize proxy derive skRm pkRm = do
    skR <- deserializeSK proxy skRm
    pkR <- deserializePublicKey proxy pkRm
    return $ newEnv derive skR pkR

----------------------------------------------------------------

ecdh'
    :: EllipticCurveDH group
    => Proxy group
    -> SecretKey group
    -> PublicKey group
    -> a
    -> Either a SharedSecret
ecdh' proxy sk pk err = case ecdh proxy sk pk of
    CryptoPassed a -> Right a
    CryptoFailed _ -> Left err
