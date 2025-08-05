{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KDF (
    HashAlgorithm,
    SHA256 (..),
    SHA384 (..),
    SHA512 (..),
    PRK (..),
    labeledExtract,
    labeledExpand,
    extractAndExpand,
)
where

import Ageha.Hash
import Ageha.KDF.HKDF

import Crypto.HPKE.Types

----------------------------------------------------------------

labeledExtract
    :: HashAlgorithm h => h -> Suite -> Salt -> Label -> IKM -> PRK
labeledExtract h suite salt label ikm = hkdfExtract h salt labeled_ikm
  where
    labeled_ikm = "HPKE-v1" <> suite <> label <> ikm

labeledExpand
    :: HashAlgorithm h => h -> Suite -> PRK -> Label -> Info -> Int -> ByteString
labeledExpand h suite prk label info len = hkdfExpand h prk labeled_info len
  where
    labeled_info =
        i2ospOf_ 2 (fromIntegral len) <> "HPKE-v1" <> suite <> label <> info

----------------------------------------------------------------

extractAndExpand
    :: HashAlgorithm h
    => h -> Suite -> KeyDeriveFunction
extractAndExpand h suite dh kem_context = Key shared_secret
  where
    eae_prk = labeledExtract h suite "" "eae_prk" $ convert dh
    siz = hashDigestSize h
    shared_secret =
        labeledExpand h suite eae_prk "shared_secret" kem_context siz
