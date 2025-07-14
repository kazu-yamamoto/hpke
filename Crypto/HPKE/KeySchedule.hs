{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.HPKE.KeySchedule (
    -- * Types
    Mode (..),

    -- * Key schedule
    keySchedule,
) where

import qualified Data.ByteString as BS

import Crypto.HPKE.KDF
import Crypto.HPKE.Types

----------------------------------------------------------------

data Mode
    = ModeBase
    | ModePsk
    | ModeAuth
    | ModeAuthPsk
    deriving (Eq, Show)

{- FOURMOLU_DISABLE -}
fromMode :: Mode -> Word8
fromMode ModeBase    = 0x00
fromMode ModePsk     = 0x01
fromMode ModeAuth    = 0x02
fromMode ModeAuthPsk = 0x03
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

keySchedule
    :: HashAlgorithm h
    => h
    -> Suite
    -> Int
    -> Int
    -> Mode
    -> Info
    -> PSK
    -> PSK_ID
    -> SharedSecret
    -> Either HPKEError (Key, Nonce, Int, PRK)
keySchedule h suite nk nn mode info psk psk_id shared_secret =
    Right (key, base_nonce, 0, PRK exporter_secret)
  where
    PRK psk_id_hash = labeledExtract h suite "" "psk_id_hash" psk_id
    PRK info_hash = labeledExtract h suite "" "info_hash" info
    key_schedule_context =
        BS.singleton (fromMode mode) <> psk_id_hash <> info_hash
            :: ByteString

    secret = labeledExtract h suite (convert shared_secret) "secret" psk

    key = labeledExpand h suite secret "key" key_schedule_context nk
    base_nonce = labeledExpand h suite secret "base_nonce" key_schedule_context nn

    exporter_secret = labeledExpand h suite secret "exp" key_schedule_context $ hashDigestSize h
