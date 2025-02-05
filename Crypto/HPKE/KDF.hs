{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KDF (
    KDF (..),
    HashAlgorithm,
    SHA256 (..),
    SHA384 (..),
    SHA512 (..),
    PRK,
    KDF_ID (HKDF_SHA256, HKDF_SHA384, HKDF_SHA512, ..),
    KDFHash (..),
    defaultKdfMap,
    extractAndExpandH,
)
where

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

-- | ID for key derivation function.
newtype KDF_ID = KDF_ID {fromKDF_ID :: Word16} deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern HKDF_SHA256 :: KDF_ID
pattern HKDF_SHA256  = KDF_ID 0x0001
pattern HKDF_SHA384 :: KDF_ID
pattern HKDF_SHA384  = KDF_ID 0x0002
pattern HKDF_SHA512 :: KDF_ID
pattern HKDF_SHA512  = KDF_ID 0x0003

instance Show KDF_ID where
    show HKDF_SHA256 = "HKDF_SHA256"
    show HKDF_SHA384 = "HKDF_SHA384"
    show HKDF_SHA512 = "HKDF_SHA512"
    show (KDF_ID n)  = "HKDF_ID 0x" ++ printf "%04x" n
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

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

----------------------------------------------------------------

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

----------------------------------------------------------------

data KDFHash = forall h. (HashAlgorithm h, KDF h) => KDFHash h

defaultKdfMap :: [(KDF_ID, KDFHash)]
defaultKdfMap =
    [ (HKDF_SHA256, KDFHash SHA256)
    , (HKDF_SHA384, KDFHash SHA384)
    , (HKDF_SHA512, KDFHash SHA512)
    ]

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
