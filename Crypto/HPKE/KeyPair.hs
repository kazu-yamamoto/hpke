{-# LANGUAGE RecordWildCards #-}

module Crypto.HPKE.KeyPair where

import qualified Control.Exception as E
import Crypto.KEM (generateKeyPair)

import Crypto.HPKE.ID
import Crypto.HPKE.KEM (HPKEKEM (..), KEMAlg (..))
import Crypto.HPKE.Map
import Crypto.HPKE.Types

----------------------------------------------------------------

-- | Generating a pair of public key and secret key based on
-- 'KEM_ID'.
genKeyPair
    :: HPKEMap -> KEM_ID -> IO (EncodedPublicKey, EncodedSecretKey)
genKeyPair HPKEMap{..} kem_id = case lookup kem_id kemMap of
    Nothing -> E.throwIO $ Unsupported $ show kem_id
    Just (KEMAlg kem) -> generateKeyPair kem

-- | The public key that goes with a secret key, for the KEM named by the
-- 'KEM_ID'.  A receiver authenticating a sender is given the sender's
-- public key; this is how the sender arrives at one to publish.
toPublicKey
    :: HPKEMap
    -> KEM_ID
    -> EncodedSecretKey
    -> Either HPKEError EncodedPublicKey
toPublicKey HPKEMap{..} kem_id skm = case lookup kem_id kemMap of
    Nothing -> Left $ Unsupported $ show kem_id
    Just (KEMAlg kem) -> toEncapsulationKey kem skm
