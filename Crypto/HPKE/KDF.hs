{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KDF (
    KDF (..),
    HashAlgorithm,
    SHA256 (..),
    SHA384 (..),
    SHA512 (..),
    PRK,
    extractAndExpand,
)
where

import Crypto.Hash.IO (hashDigestSize)
import Crypto.Hash.Algorithms (
    HashAlgorithm,
    SHA256 (..),
    SHA384 (..),
    SHA512 (..),
 )
import Crypto.KDF.HKDF (PRK)
import qualified Crypto.KDF.HKDF as HKDF

import Crypto.HPKE.Types

----------------------------------------------------------------

class KDF h where
    labeledExtract :: Suite -> Salt -> Label -> IKM -> PRK h

    -- | RFC 9180 section 5.3 allows an output of at most @255 * Nh@ octets,
    -- which is also what HKDF's counter can reach.  A longer one is refused
    -- here rather than left to the HKDF underneath, whose way of saying so
    -- is an exception.
    labeledExpand
        :: Suite -> PRK h -> Label -> Info -> Int -> Either HPKEError Key

instance KDF SHA256 where
    labeledExtract = labeledExtract_
    labeledExpand = labeledExpand_

instance KDF SHA384 where
    labeledExtract = labeledExtract_
    labeledExpand = labeledExpand_

instance KDF SHA512 where
    labeledExtract = labeledExtract_
    labeledExpand = labeledExpand_

----------------------------------------------------------------

labeledExtract_
    :: HashAlgorithm a => Suite -> Salt -> Label -> IKM -> PRK a
labeledExtract_ suite salt label ikm = HKDF.extract salt labeled_ikm
  where
    labeled_ikm = "HPKE-v1" <> suite <> label <> ikm

labeledExpand_
    :: forall a
     . HashAlgorithm a
    => Suite -> PRK a -> Label -> Info -> Int -> Either HPKEError Key
labeledExpand_ suite prk label info len
    | len < 0 || len > maxLen =
        Left $
            ExportError $
                "length "
                    ++ show len
                    ++ " is outside 0 .. "
                    ++ show maxLen
    | otherwise = Right $ HKDF.expand prk labeled_info len
  where
    maxLen = 255 * hashDigestSize (undefined :: a)
    labeled_info =
        i2ospOf_ 2 (fromIntegral len) <> "HPKE-v1" <> suite <> label <> info

----------------------------------------------------------------

extractAndExpand
    :: forall h
     . (HashAlgorithm h, KDF h)
    => h -> Suite -> KeyDeriveFunction
extractAndExpand h suite dh kem_context = shared_secret
  where
    eae_prk :: PRK h
    eae_prk = labeledExtract suite "" "eae_prk" $ convert dh
    siz = hashDigestSize h
    -- the hash's own digest size, so the length is in range by construction
    shared_secret =
        either (const "") id $
            labeledExpand suite eae_prk "shared_secret" kem_context siz
