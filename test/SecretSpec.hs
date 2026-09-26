{-# LANGUAGE OverloadedStrings #-}

module SecretSpec where

import Crypto.Debug (debugShow)
import Crypto.HPKE
import Data.List (isInfixOf)
import Test.Hspec

-- | A secret key is what a caller stores and what a debugging line prints,
-- so 'Show' does not render it and 'debugShow' does.
spec :: Spec
spec = describe "Show of an encoded key" $ do
    it "does not print a secret key" $ do
        show sk `shouldBe` "<secret>"
        hex `isInfixOf` debugShow sk `shouldBe` True
    it "still prints a public key" $
        hex `isInfixOf` show (EncodedPublicKey "\x01\x23\x45\x67") `shouldBe` True
  where
    sk = EncodedSecretKey "\x01\x23\x45\x67"
    hex = "01234567"
