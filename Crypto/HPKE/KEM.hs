{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Crypto.HPKE.KEM (
    HPKEKEM (..),
    KEMAlg (..),
    encapEnv,
    decapEnv,
)
where

import Crypto.ECC (
    EllipticCurve (..),
    EllipticCurveDH (..),
 )
import Crypto.KEM (KEM (..))
import Crypto.Random (MonadRandom)

import Crypto.HPKE.PublicKey
import Crypto.HPKE.Types

----------------------------------------------------------------

-- | What HPKE needs of a KEM beyond what @crypton@'s 'KEM' class says.
--
-- RFC 9180 section 4.1 gives DHKEM four operations and the class has room
-- for two: @Encap@ is 'encapsulate', @Decap@ is 'decapsulate'.  @AuthEncap@
-- and @AuthDecap@ take a static sender key, which the class has no argument
-- for, so they are here.  They default to refusing, which is what a KEM
-- with no authenticated mode -- any post-quantum one -- should do.
--
-- The equalities pin the four associated types to the serialized forms of
-- section 4, which is what travels and what this package's entry points
-- take, so that 'Crypto.HPKE.setupS' can be written once for every KEM.
class
    ( KEM kem
    , EncapsulationKey kem ~ EncodedPublicKey
    , DecapsulationKey kem ~ EncodedSecretKey
    , Ciphertext kem ~ EncodedPublicKey
    , Coins kem ~ EncodedSecretKey
    ) =>
    HPKEKEM kem
    where
    -- | Draw what 'encapsulate' would have drawn, so that the
    -- authenticated forms can generate their ephemeral key the same way.
    --
    -- For every KEM here the coins are a secret key, so the default is to
    -- draw a key pair and keep the half that is one.
    generateCoins :: MonadRandom m => proxy kem -> m EncodedSecretKey
    generateCoins p = snd `fmap` generateKeyPair p

    -- | @AuthEncap@ of section 4.1, with the ephemeral key supplied.
    authEncapWith
        :: proxy kem
        -> EncodedSecretKey
        -- ^ @skS@, the sender's static key
        -> EncodedPublicKey
        -- ^ @pkR@
        -> EncodedSecretKey
        -- ^ @skE@
        -> Either HPKEError (EncodedPublicKey, SharedSecret)
    authEncapWith _ _ _ _ = Left $ Unsupported "authenticated mode"

    -- | @AuthDecap@ of section 4.1.  The sender is named by its public
    -- key: a receiver does not have the other side's secret key, and
    -- asking for one would be asking for the wrong thing.
    authDecap
        :: proxy kem
        -> EncodedPublicKey
        -- ^ @pkS@, the sender's static public key
        -> EncodedSecretKey
        -- ^ @skR@
        -> EncodedPublicKey
        -- ^ @enc@
        -> Either HPKEError SharedSecret
    authDecap _ _ _ _ = Left $ Unsupported "authenticated mode"

    -- | The encapsulation key a decapsulation key belongs to.
    toEncapsulationKey
        :: proxy kem -> EncodedSecretKey -> Either HPKEError EncodedPublicKey

-- | A KEM that HPKE can run over, with its identity forgotten, for the
-- table that turns a @KEM_ID@ into one.
data KEMAlg = forall kem. HPKEKEM kem => KEMAlg (Proxy kem)

----------------------------------------------------------------

-- | @Encap@ and @AuthEncap@ of RFC 9180 section 4.1, with the ephemeral key
-- supplied.
--
-- Written out the same way 'decap' is: what it needs are the ephemeral key,
-- the sender's static key if the mode is authenticated, and the recipient's
-- public key.
encap
    :: (EllipticCurve group, EllipticCurveDH group)
    => Proxy group
    -> KeyDeriveFunction
    -> SecretKey group
    -> Maybe (SecretKey group)
    -> Encap
encap proxy derive skE mskS enc0@(EncodedPublicKey pkRm) = do
    pkR <- deserializePublicKey proxy enc0
    dh0 <- ecdh' proxy skE pkR $ EncapError "encap"
    (dh, pkSm) <- case mskS of
        Nothing -> return (dh0, "")
        Just skS -> do
            let pkS = scalarToPoint proxy skS
            dh1 <- ecdh' proxy skS pkR $ EncapError "encap"
            let EncodedPublicKey pk = serializePublicKey proxy pkS
            return (dh0 <> dh1, pk)
    let pkE = scalarToPoint proxy skE
    let enc@(EncodedPublicKey pkEm) = serializePublicKey proxy pkE
        kem_context = pkEm <> pkRm <> pkSm
        shared_secret = SharedSecret $ convert $ derive dh kem_context
    return (shared_secret, enc)

encapEnv
    :: (EllipticCurve group, EllipticCurveDH group)
    => Proxy group
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> Maybe EncodedSecretKey
    -> Encap
encapEnv proxy derive skEm mskSm enc = do
    skE <- deserializeSecretKey proxy skEm
    mskS <- traverse (deserializeSecretKey proxy) mskSm
    encap proxy derive skE mskS enc

----------------------------------------------------------------

-- | @Decap@ and @AuthDecap@ of RFC 9180 section 4.1.
--
-- The sender is named by its public key, because that is all a receiver
-- has: @AuthDecap(enc, skR, pkS)@.
decap
    :: (EllipticCurve group, EllipticCurveDH group)
    => Proxy group
    -> KeyDeriveFunction
    -> SecretKey group
    -> Maybe (PublicKey group)
    -> Decap
decap proxy derive skR mpkS enc@(EncodedPublicKey pkEm) = do
    pkE <- deserializePublicKey proxy enc
    dh0 <- ecdh' proxy skR pkE $ DecapError "decap"
    (dh, pkSm) <- case mpkS of
        Nothing -> return (dh0, "")
        Just pkS -> do
            dh1 <- ecdh' proxy skR pkS $ DecapError "decap"
            let EncodedPublicKey pk = serializePublicKey proxy pkS
            return (dh0 <> dh1, pk)
    let pkR = scalarToPoint proxy skR
    let EncodedPublicKey pkRm = serializePublicKey proxy pkR
        kem_context = pkEm <> pkRm <> pkSm
        shared_secret = SharedSecret $ convert $ derive dh kem_context
    return shared_secret

decapEnv
    :: (EllipticCurve group, EllipticCurveDH group)
    => Proxy group
    -> KeyDeriveFunction
    -> EncodedSecretKey
    -> Maybe EncodedPublicKey
    -> Decap
decapEnv proxy derive skRm mpkSm enc = do
    skR <- deserializeSecretKey proxy skRm
    mpkS <- traverse (deserializePublicKey proxy) mpkSm
    decap proxy derive skR mpkS enc

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
