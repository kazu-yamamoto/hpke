{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

-- | DHKEM as an instance of @crypton@'s 'KEM' class.
--
-- RFC 9180 section 4.1 builds a key encapsulation mechanism out of a
-- Diffie-Hellman group: the exchange's output goes through HKDF with the
-- ephemeral and the recipient public keys as context, under labels that
-- name the ciphersuite.  That construction, and not the bare exchange, is
-- what a KEM is, which is why @crypton@ has the class and no instance for
-- the groups themselves.
--
-- There is one type per suite RFC 9180 registers, and no way to spell
-- anything else.  The group does not pick the suite on its own -- the hash
-- and the registered code point are part of what the shared secret is
-- derived from -- but the registry lists each group exactly once, so
-- naming the group names all three.
--
-- The instance is here rather than in @crypton@ because those labels carry
-- the HPKE ciphersuite identifier and the protocol's own version string,
-- which is the same reason TLS 1.3's labelled HKDF lives in @tls@ rather
-- than in @crypton@.
--
-- Only @Encap@ and @Decap@ are instance methods.  DHKEM also has
-- @AuthEncap@ and @AuthDecap@, in that same section 4.1, where a static
-- sender key contributes a second Diffie-Hellman and its public key joins
-- the context; they take an argument the class has no room for, so they
-- are not here.  'Crypto.HPKE.setupBaseS' with a sender key is the way to
-- those, through the mode of section 5.1.3.
module Crypto.HPKE.DHKEM (
    -- * The suites RFC 9180 registers
    DHKEM_P256,
    DHKEM_P384,
    DHKEM_P521,
    DHKEM_X25519,
    DHKEM_X448,

    -- * The classes they implement
    KEM (..),
    HPKEKEM (..),
    SharedSecret (..),
) where

import Crypto.ECC (
    Curve_P256R1,
    Curve_P384R1,
    Curve_P521R1,
    Curve_X25519,
    Curve_X448,
    EllipticCurve (..),
    EllipticCurveDH (..),
    KeyPair (..),
 )
import Crypto.Error (CryptoError (..))
import Crypto.KEM (KEM (..))
import Crypto.Random (MonadRandom)
import Data.Kind (Type)

import Crypto.HPKE.ID
import Crypto.HPKE.KDF
import Crypto.HPKE.KEM
import Crypto.HPKE.PublicKey
import Crypto.HPKE.Types

----------------------------------------------------------------

-- | DHKEM(P-256, HKDF-SHA256).
data DHKEM_P256

-- | DHKEM(P-384, HKDF-SHA384).
data DHKEM_P384

-- | DHKEM(P-521, HKDF-SHA512).
data DHKEM_P521

-- | DHKEM(X25519, HKDF-SHA256).
data DHKEM_X25519

-- | DHKEM(X448, HKDF-SHA512).
data DHKEM_X448

----------------------------------------------------------------

-- What a registered suite is made of.  Not exported: it exists so that the
-- five instances below are five names rather than five copies of the same
-- code, and a sixth suite would be a line here and not a design.
class
    ( EllipticCurve (HPKEKEMGroup kem)
    , EllipticCurveDH (HPKEKEMGroup kem)
    , HashAlgorithm (HPKEKEMHash kem)
    , KDF (HPKEKEMHash kem)
    ) =>
    HPKEKEMRegistered kem
    where
    type HPKEKEMGroup kem :: Type
    type HPKEKEMHash kem :: Type
    hpkeKEMID :: proxy kem -> KEM_ID
    hpkeKEMHash :: proxy kem -> HPKEKEMHash kem

{- FOURMOLU_DISABLE -}
instance HPKEKEMRegistered DHKEM_P256 where
    type HPKEKEMGroup DHKEM_P256    = Curve_P256R1
    type HPKEKEMHash  DHKEM_P256    = SHA256
    hpkeKEMID   _ = DHKEM_P256_HKDF_SHA256
    hpkeKEMHash _ = SHA256

instance HPKEKEMRegistered DHKEM_P384 where
    type HPKEKEMGroup DHKEM_P384    = Curve_P384R1
    type HPKEKEMHash  DHKEM_P384    = SHA384
    hpkeKEMID   _ = DHKEM_P384_HKDF_SHA384
    hpkeKEMHash _ = SHA384

instance HPKEKEMRegistered DHKEM_P521 where
    type HPKEKEMGroup DHKEM_P521    = Curve_P521R1
    type HPKEKEMHash  DHKEM_P521    = SHA512
    hpkeKEMID   _ = DHKEM_P521_HKDF_SHA512
    hpkeKEMHash _ = SHA512

instance HPKEKEMRegistered DHKEM_X25519 where
    type HPKEKEMGroup DHKEM_X25519  = Curve_X25519
    type HPKEKEMHash  DHKEM_X25519  = SHA256
    hpkeKEMID   _ = DHKEM_X25519_HKDF_SHA256
    hpkeKEMHash _ = SHA256

instance HPKEKEMRegistered DHKEM_X448 where
    type HPKEKEMGroup DHKEM_X448    = Curve_X448
    type HPKEKEMHash  DHKEM_X448    = SHA512
    hpkeKEMID   _ = DHKEM_X448_HKDF_SHA512
    hpkeKEMHash _ = SHA512
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

-- | The keys and the encapsulated value are the serialized forms of RFC
-- 9180 section 4, which is what travels and what this package's other
-- entry points already speak.  The coins are the sender's ephemeral secret
-- key, @skE@, which is what the appendix A vectors fix.
instance KEM DHKEM_P256 where
    type EncapsulationKey DHKEM_P256 = EncodedPublicKey
    type DecapsulationKey DHKEM_P256 = EncodedSecretKey
    type Ciphertext DHKEM_P256 = EncodedPublicKey
    type Coins DHKEM_P256 = EncodedSecretKey
    generateKeyPair = dhkemGenerateKeyPair
    encapsulate = dhkemEncapsulate
    encapsulateWith = dhkemEncapsulateWith
    decapsulate = dhkemDecapsulate

instance KEM DHKEM_P384 where
    type EncapsulationKey DHKEM_P384 = EncodedPublicKey
    type DecapsulationKey DHKEM_P384 = EncodedSecretKey
    type Ciphertext DHKEM_P384 = EncodedPublicKey
    type Coins DHKEM_P384 = EncodedSecretKey
    generateKeyPair = dhkemGenerateKeyPair
    encapsulate = dhkemEncapsulate
    encapsulateWith = dhkemEncapsulateWith
    decapsulate = dhkemDecapsulate

instance KEM DHKEM_P521 where
    type EncapsulationKey DHKEM_P521 = EncodedPublicKey
    type DecapsulationKey DHKEM_P521 = EncodedSecretKey
    type Ciphertext DHKEM_P521 = EncodedPublicKey
    type Coins DHKEM_P521 = EncodedSecretKey
    generateKeyPair = dhkemGenerateKeyPair
    encapsulate = dhkemEncapsulate
    encapsulateWith = dhkemEncapsulateWith
    decapsulate = dhkemDecapsulate

instance KEM DHKEM_X25519 where
    type EncapsulationKey DHKEM_X25519 = EncodedPublicKey
    type DecapsulationKey DHKEM_X25519 = EncodedSecretKey
    type Ciphertext DHKEM_X25519 = EncodedPublicKey
    type Coins DHKEM_X25519 = EncodedSecretKey
    generateKeyPair = dhkemGenerateKeyPair
    encapsulate = dhkemEncapsulate
    encapsulateWith = dhkemEncapsulateWith
    decapsulate = dhkemDecapsulate

instance KEM DHKEM_X448 where
    type EncapsulationKey DHKEM_X448 = EncodedPublicKey
    type DecapsulationKey DHKEM_X448 = EncodedSecretKey
    type Ciphertext DHKEM_X448 = EncodedPublicKey
    type Coins DHKEM_X448 = EncodedSecretKey
    generateKeyPair = dhkemGenerateKeyPair
    encapsulate = dhkemEncapsulate
    encapsulateWith = dhkemEncapsulateWith
    decapsulate = dhkemDecapsulate

----------------------------------------------------------------

-- | DHKEM has all four operations of RFC 9180 section 4.1, so the
-- authenticated pair is defined rather than left to refuse.
instance HPKEKEM DHKEM_P256 where
    authEncapWith = dhkemAuthEncapWith
    authDecap = dhkemAuthDecap
    toEncapsulationKey = dhkemToEncapsulationKey

instance HPKEKEM DHKEM_P384 where
    authEncapWith = dhkemAuthEncapWith
    authDecap = dhkemAuthDecap
    toEncapsulationKey = dhkemToEncapsulationKey

instance HPKEKEM DHKEM_P521 where
    authEncapWith = dhkemAuthEncapWith
    authDecap = dhkemAuthDecap
    toEncapsulationKey = dhkemToEncapsulationKey

instance HPKEKEM DHKEM_X25519 where
    authEncapWith = dhkemAuthEncapWith
    authDecap = dhkemAuthDecap
    toEncapsulationKey = dhkemToEncapsulationKey

instance HPKEKEM DHKEM_X448 where
    authEncapWith = dhkemAuthEncapWith
    authDecap = dhkemAuthDecap
    toEncapsulationKey = dhkemToEncapsulationKey

----------------------------------------------------------------

dhkemAuthEncapWith
    :: HPKEKEMRegistered kem
    => proxy kem
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> EncodedSecretKey
    -> Either HPKEError (EncodedPublicKey, SharedSecret)
dhkemAuthEncapWith p skSm pkRm skEm =
    flop <$> encapEnv (groupOf p) (deriveOf p) skEm (Just skSm) pkRm

dhkemAuthDecap
    :: HPKEKEMRegistered kem
    => proxy kem
    -> EncodedPublicKey
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Either HPKEError SharedSecret
dhkemAuthDecap p pkSm skRm enc =
    decapEnv (groupOf p) (deriveOf p) skRm (Just pkSm) enc

dhkemToEncapsulationKey
    :: HPKEKEMRegistered kem
    => proxy kem -> EncodedSecretKey -> Either HPKEError EncodedPublicKey
dhkemToEncapsulationKey p skm =
    serializePublicKey g . scalarToPoint g <$> deserializeSecretKey g skm
  where
    g = groupOf p

flop :: (SharedSecret, EncodedPublicKey) -> (EncodedPublicKey, SharedSecret)
flop (ss, enc) = (enc, ss)

----------------------------------------------------------------

dhkemGenerateKeyPair
    :: (HPKEKEMRegistered kem, MonadRandom m)
    => proxy kem -> m (EncodedPublicKey, EncodedSecretKey)
dhkemGenerateKeyPair p = do
    KeyPair pk sk <- curveGenerateKeyPair g
    return (serializePublicKey g pk, serializeSecretKey g sk)
  where
    g = groupOf p

dhkemEncapsulate
    :: (HPKEKEMRegistered kem, MonadRandom m)
    => proxy kem
    -> EncodedPublicKey
    -> m (CryptoFailable (EncodedPublicKey, SharedSecret))
dhkemEncapsulate p pkRm =
    dhkemEncapsulateWith p pkRm . snd <$> dhkemGenerateKeyPair p

dhkemEncapsulateWith
    :: HPKEKEMRegistered kem
    => proxy kem
    -> EncodedPublicKey
    -> EncodedSecretKey
    -> CryptoFailable (EncodedPublicKey, SharedSecret)
dhkemEncapsulateWith p pkRm skEm =
    toCryptoFailable $ flop <$> encapEnv (groupOf p) (deriveOf p) skEm Nothing pkRm

dhkemDecapsulate
    :: HPKEKEMRegistered kem
    => proxy kem
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> CryptoFailable SharedSecret
dhkemDecapsulate p skRm enc =
    toCryptoFailable $ decapEnv (groupOf p) (deriveOf p) skRm Nothing enc

----------------------------------------------------------------

groupOf :: proxy kem -> Proxy (HPKEKEMGroup kem)
groupOf _ = Proxy

deriveOf :: forall proxy kem. HPKEKEMRegistered kem => proxy kem -> KeyDeriveFunction
deriveOf p = extractAndExpand (hpkeKEMHash p) (suiteKEM (hpkeKEMID p))

-- | The class answers with a 'CryptoFailable', which carries a reason from
-- a fixed list and not a message.  What is lost is the string; what each
-- error means is kept.  'Crypto.HPKE.setupBaseS' and its neighbours still
-- throw the 'HPKEError' with its message.
toCryptoFailable :: Either HPKEError a -> CryptoFailable a
toCryptoFailable (Right a) = CryptoPassed a
toCryptoFailable (Left e) = CryptoFailed $ case e of
    DeserializeError _ -> CryptoError_PointFormatInvalid
    EncapError _ -> CryptoError_ScalarMultiplicationInvalid
    DecapError _ -> CryptoError_ScalarMultiplicationInvalid
    _ -> CryptoError_ParameterInvalid
