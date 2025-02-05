{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

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

type PublicKey curve = Point curve
type SecretKey curve = Scalar curve

data Env curve = Env
    { envSecretKey :: SecretKey curve
    , envPublicKey :: PublicKey curve
    , envProxy :: Proxy curve
    , envDerive :: KeyDeriveFunction
    }

----------------------------------------------------------------

-- |
--
-- >>> let skEm = "\x52\xc4\xa7\x58\xa8\x02\xcd\x8b\x93\x6e\xce\xea\x31\x44\x32\x79\x8d\x5b\xaf\x2d\x7e\x92\x35\xdc\x08\x4a\xb1\xb9\xcf\xa2\xf7\x36" :: SecretKey Curve_X25519
-- >>> let pkEm = "\x37\xfd\xa3\x56\x7b\xdb\xd6\x28\xe8\x86\x68\xc3\xc8\xd7\xe9\x7d\x1d\x12\x53\xb6\xd4\xea\x6d\x44\xc1\x50\xf7\x41\xf1\xbf\x44\x31" :: PublicKey Curve_X25519
-- >>> let pkRm = "\x39\x48\xcf\xe0\xad\x1d\xdb\x69\x5d\x78\x0e\x59\x07\x71\x95\xda\x6c\x56\x50\x6b\x02\x73\x29\x79\x4a\xb0\x2b\xca\x80\x81\x5c\x4d" :: EncodedPublicKey
-- >>> let env = newEnv DHKEM_X25519_HKDF_SHA256 skEm pkEm :: Env Curve_X25519
-- >>> encap env pkRm
-- ("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc","37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
encap
    :: (EllipticCurve curve, EllipticCurveDH curve)
    => Env curve
    -> Encap
encap Env{..} (EncodedPublicKey pkRm) =
    (shared_secret, EncodedPublicKey enc)
  where
    pkR = noFail $ decodePoint envProxy pkRm
    dh = noFail $ ecdh envProxy envSecretKey pkR
    enc = encodePoint envProxy envPublicKey
    kem_context = enc <> pkRm
    shared_secret = SharedSecret $ convert $ envDerive dh kem_context

encapGen
    :: KEM_ID
    -> IO Encap
encapGen kem_id@DHKEM_P256_HKDF_SHA256 = do
    let proxy = Proxy :: Proxy Curve_P256R1
    env <- genEnv proxy kem_id
    return $ encap env
encapGen kem_id@DHKEM_P384_HKDF_SHA384 = do
    let proxy = Proxy :: Proxy Curve_P384R1
    env <- genEnv proxy kem_id
    return $ encap env
encapGen kem_id@DHKEM_P512_HKDF_SHA512 = do
    let proxy = Proxy :: Proxy Curve_P521R1
    env <- genEnv proxy kem_id
    return $ encap env
encapGen kem_id@DHKEM_X25519_HKDF_SHA256 = do
    let proxy = Proxy :: Proxy Curve_X25519
    env <- genEnv proxy kem_id
    return $ encap env
encapGen kem_id@DHKEM_X448_HKDF_SHA512 = do
    let proxy = Proxy :: Proxy Curve_X448
    env <- genEnv proxy kem_id
    return $ encap env
encapGen _ = error "encapGen"

encapKEM
    :: KEM_ID
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Encap
encapKEM kem_id@DHKEM_P256_HKDF_SHA256 skRm pkRm = encap env
  where
    env = newEnvP kem_id skRm pkRm :: Env Curve_P256R1
encapKEM kem_id@DHKEM_P384_HKDF_SHA384 skRm pkRm = encap env
  where
    env = newEnvP kem_id skRm pkRm :: Env Curve_P384R1
encapKEM kem_id@DHKEM_P512_HKDF_SHA512 skRm pkRm = encap env
  where
    env = newEnvP kem_id skRm pkRm :: Env Curve_P521R1
encapKEM kem_id@DHKEM_X25519_HKDF_SHA256 (EncodedSecretKey skRm) (EncodedPublicKey pkRm) = encap env
  where
    skR = noFail $ X25519.secretKey skRm
    pkR = noFail $ X25519.publicKey pkRm
    env = newEnv kem_id skR pkR :: Env Curve_X25519
encapKEM kem_id@DHKEM_X448_HKDF_SHA512 (EncodedSecretKey skRm) (EncodedPublicKey pkRm) = encap env
  where
    skR = noFail $ X448.secretKey skRm
    pkR = noFail $ X448.publicKey pkRm
    env = newEnv kem_id skR pkR :: Env Curve_X448
encapKEM _ _ _ = error "encapKEM"

----------------------------------------------------------------

-- |
--
-- >>> let skRm = "\x46\x12\xc5\x50\x26\x3f\xc8\xad\x58\x37\x5d\xf3\xf5\x57\xaa\xc5\x31\xd2\x68\x50\x90\x3e\x55\xa9\xf2\x3f\x21\xd8\x53\x4e\x8a\xc8" :: SecretKey Curve_X25519
-- >>> let pkRm = "\x39\x48\xcf\xe0\xad\x1d\xdb\x69\x5d\x78\x0e\x59\x07\x71\x95\xda\x6c\x56\x50\x6b\x02\x73\x29\x79\x4a\xb0\x2b\xca\x80\x81\x5c\x4d" :: PublicKey Curve_X25519
-- >>> let env = newEnv DHKEM_X25519_HKDF_SHA256 skRm pkRm :: Env Curve_X25519
-- >>> let enc = "\x37\xfd\xa3\x56\x7b\xdb\xd6\x28\xe8\x86\x68\xc3\xc8\xd7\xe9\x7d\x1d\x12\x53\xb6\xd4\xea\x6d\x44\xc1\x50\xf7\x41\xf1\xbf\x44\x31" :: EncodedPublicKey
-- >>> decap env enc
-- "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"
decap
    :: (EllipticCurve curve, EllipticCurveDH curve)
    => Env curve
    -> Decap
decap Env{..} (EncodedPublicKey enc) = shared_secret
  where
    pkE = noFail $ decodePoint envProxy enc
    dh = noFail $ ecdh envProxy envSecretKey pkE
    pkRm = encodePoint envProxy envPublicKey
    kem_context = enc <> pkRm
    shared_secret = SharedSecret $ convert $ envDerive dh kem_context

decapKEM
    :: KEM_ID
    -> EncodedSecretKey
    -> EncodedPublicKey
    -> Decap
decapKEM kem_id@DHKEM_P256_HKDF_SHA256 skRm pkRm = decap env
  where
    env = newEnvP kem_id skRm pkRm :: Env Curve_P256R1
decapKEM kem_id@DHKEM_P384_HKDF_SHA384 skRm pkRm = decap env
  where
    env = newEnvP kem_id skRm pkRm :: Env Curve_P384R1
decapKEM kem_id@DHKEM_P512_HKDF_SHA512 skRm pkRm = decap env
  where
    env = newEnvP kem_id skRm pkRm :: Env Curve_P521R1
decapKEM kem_id@DHKEM_X25519_HKDF_SHA256 (EncodedSecretKey skRm) (EncodedPublicKey pkRm) = decap env
  where
    skR = noFail $ X25519.secretKey skRm
    pkR = noFail $ X25519.publicKey pkRm
    env = newEnv kem_id skR pkR :: Env Curve_X25519
decapKEM kem_id@DHKEM_X448_HKDF_SHA512 (EncodedSecretKey skRm) (EncodedPublicKey pkRm) = decap env
  where
    skR = noFail $ X448.secretKey skRm
    pkR = noFail $ X448.publicKey pkRm
    env = newEnv kem_id skR pkR :: Env Curve_X448
decapKEM _ _ _ = error "decapKEM"

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
kemTokdf :: KEM_ID -> KDF_ID
kemTokdf DHKEM_P256_HKDF_SHA256   = HKDF_SHA256
kemTokdf DHKEM_P384_HKDF_SHA384   = HKDF_SHA384
kemTokdf DHKEM_P512_HKDF_SHA512   = HKDF_SHA512
kemTokdf DHKEM_X25519_HKDF_SHA256 = HKDF_SHA256
kemTokdf DHKEM_X448_HKDF_SHA512   = HKDF_SHA512
kemTokdf _                        = error "kemTokdf"
{- FOURMOLU_ENABLE -}

newEnv
    :: forall curve
     . EllipticCurve curve
    => KEM_ID -> SecretKey curve -> PublicKey curve -> (Env curve)
newEnv kem_id skR pkR =
    Env
        { envSecretKey = skR
        , envPublicKey = pkR
        , envProxy = proxy
        , envDerive = extractAndExpandKDF (kemTokdf kem_id) suite
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
    return $ newEnv kem_id sk pk

newEnvP
    :: forall curve
     . (EllipticCurve curve, EllipticCurveBasepointArith curve)
    => KEM_ID -> EncodedSecretKey -> EncodedPublicKey -> Env curve
newEnvP kem_id (EncodedSecretKey skRm) (EncodedPublicKey pkRm) = env
  where
    proxy = Proxy :: Proxy curve
    skR = noFail (decodeScalar proxy skRm) :: SecretKey curve
    pkR = noFail (decodePoint proxy pkRm) :: PublicKey curve
    env = newEnv kem_id skR pkR :: Env curve

----------------------------------------------------------------

suiteKEM :: KEM_ID -> Suite
suiteKEM kem_id = "KEM" <> i
  where
    i = i2ospOf_ 2 $ fromIntegral $ fromKEM_ID kem_id
