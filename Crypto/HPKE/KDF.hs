{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KDF (
    KDF (..),
    SHA256,
    SHA384,
    SHA512,
    PRK,
    suiteKEM,
    suiteHPKE,
    extractAndExpandKDF,
    extractAndExpandKEM,
)
where

import Crypto.KDF.HKDF (PRK)
import qualified Crypto.KDF.HKDF as HKDF

import Crypto.HPKE.ID
import Crypto.HPKE.Types

class KDF h where
    labeledExtract :: Suite -> Salt -> Label -> IKM -> PRK h
    labeledExpand :: Suite -> PRK h -> Label -> Info -> Int -> Key

instance KDF SHA256 where
    labeledExtract = labeledExtract_
    labeledExpand = labeledExpand_

instance KDF SHA384 where
    labeledExtract = labeledExtract_
    labeledExpand = labeledExpand_

instance KDF SHA512 where
    labeledExtract = labeledExtract_
    labeledExpand = labeledExpand_

suiteKEM :: KEM_ID -> Suite
suiteKEM kem_id = "KEM" <> i
  where
    i = i2ospOf_ 2 $ fromIntegral $ fromKEM_ID kem_id

suiteHPKE :: KEM_ID -> KDF_ID -> AEAD_ID -> Suite
suiteHPKE kem_id hkdf_id aead_id = "HPKE" <> i0 <> i1 <> i2
  where
    i0 = i2ospOf_ 2 $ fromIntegral $ fromKEM_ID kem_id
    i1 = i2ospOf_ 2 $ fromIntegral $ fromKDF_ID hkdf_id
    i2 = i2ospOf_ 2 $ fromIntegral $ fromAEAD_ID aead_id

labeledExtract_
    :: HashAlgorithm a => Suite -> Salt -> Label -> IKM -> PRK a
labeledExtract_ suite salt label ikm = HKDF.extract salt labeled_ikm
  where
    labeled_ikm = "HPKE-v1" <> suite <> label <> ikm

labeledExpand_
    :: HashAlgorithm a => Suite -> PRK a -> Label -> Info -> Int -> Key
labeledExpand_ suite prk label info len = HKDF.expand prk labeled_info len
  where
    labeled_info =
        i2ospOf_ 2 (fromIntegral len) <> "HPKE-v1" <> suite <> label <> info

extractAndExpandH
    :: forall h
     . (HashAlgorithm h, KDF h)
    => h -> Suite -> SharedSecret -> ByteString -> Key
extractAndExpandH h suite dh kem_context = shared_secret
  where
    eae_prk :: PRK h
    eae_prk = labeledExtract suite "" "eae_prk" $ convert dh
    siz = hashDigestSize h
    shared_secret =
        labeledExpand suite eae_prk "shared_secret" kem_context siz

extractAndExpandKDF :: KDF_ID -> KeyDeriveFunction
extractAndExpandKDF HKDF_SHA256 = extractAndExpandH SHA256
extractAndExpandKDF HKDF_SHA384 = extractAndExpandH SHA384
extractAndExpandKDF HKDF_SHA512 = extractAndExpandH SHA512
extractAndExpandKDF _ = error "extractAndExpandKDF"

{- FOURMOLU_DISABLE -}
extractAndExpandKEM :: KEM_ID -> KeyDeriveFunction
extractAndExpandKEM DHKEM_P256_HKDF_SHA256   = extractAndExpandH SHA256
extractAndExpandKEM DHKEM_P384_HKDF_SHA384   = extractAndExpandH SHA384
extractAndExpandKEM DHKEM_P512_HKDF_SHA512   = extractAndExpandH SHA512
extractAndExpandKEM DHKEM_X25519_HKDF_SHA256 = extractAndExpandH SHA256
extractAndExpandKEM DHKEM_X448_HKDF_SHA512   = extractAndExpandH SHA512
extractAndExpandKEM _ = error "extractAndExpandKEM"
{- FOURMOLU_ENABLE -}
