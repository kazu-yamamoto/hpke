{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KEM (
    encapGen,
    encapEnv,
    decapEnv,
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
    let skE = envSecretKey
    dh <- ecdh' envProxy skE pkR $ EncapError "encap"
    let pkE = scalarToPoint envProxy skE
    let enc@(EncodedPublicKey pkEm) = serializePublicKey envProxy pkE
        kem_context = pkEm <> pkRm
        shared_secret = SharedSecret $ convert $ envDerive dh kem_context
    return (shared_secret, enc)

encapGen
    :: (EllipticCurve group, EllipticCurveDH group)
    => Proxy group
    -> KeyDeriveFunction
    -> IO Encap
encapGen proxy derive = do
    env <- genEnv proxy derive
    return $ encap env

encapEnv
    :: (EllipticCurve group, EllipticCurveDH group)
    => Proxy group
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> Encap
encapEnv proxy derive skRm enc = do
    env <- newEnvDeserialize proxy derive skRm
    encap env enc

----------------------------------------------------------------

decap
    :: (EllipticCurve group, EllipticCurveDH group)
    => Env group
    -> Decap
decap Env{..} enc@(EncodedPublicKey pkEm) = do
    pkE <- deserializePublicKey envProxy enc
    let skR = envSecretKey
    dh <- ecdh' envProxy skR pkE $ DecapError "decap"
    let pkR = scalarToPoint envProxy skR
    let EncodedPublicKey pkRm = serializePublicKey envProxy pkR
        kem_context = pkEm <> pkRm
        shared_secret = SharedSecret $ convert $ envDerive dh kem_context
    return shared_secret

decapEnv
    :: (EllipticCurve group, EllipticCurveDH group)
    => Proxy group
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> Decap
decapEnv proxy derive skRm enc = do
    env <- newEnvDeserialize proxy derive skRm
    decap env enc

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
data Env group = Env
    { envSecretKey :: SecretKey group
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
    -> Env group
newEnv derive skR =
    Env
        { envSecretKey = skR
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
    let (KeyPair _ sk, _) = withDRG gen $ curveGenerateKeyPair proxy
    return $ newEnv derive sk

----------------------------------------------------------------

newEnvDeserialize
    :: EllipticCurve group
    => Proxy group
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> Either HPKEError (Env group)
newEnvDeserialize proxy derive skRm = do
    skR <- deserializeSecretKey proxy skRm
    return $ newEnv derive skR

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
