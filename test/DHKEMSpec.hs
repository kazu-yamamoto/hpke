{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module DHKEMSpec where

import Crypto.Error (CryptoFailable (..))
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as B16
import Data.Proxy (Proxy (..))
import Test.Hspec

import Crypto.HPKE
import Crypto.HPKE.DHKEM

x25519 :: Proxy DHKEM_X25519
x25519 = Proxy

p256 :: Proxy DHKEM_P256
p256 = Proxy

hex :: ByteString -> ByteString
hex = B16.decodeLenient

-- RFC 9180 A.1.1, DHKEM(X25519, HKDF-SHA256).  The four keys are the ones
-- A1Spec already drives the whole of HPKE with; the shared secret is the
-- value the appendix gives for the KEM step alone, which nothing else here
-- reaches.
skEm, pkEm, skRm, pkRm, sharedSecret :: ByteString
skEm = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"
pkEm = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
skRm = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"
pkRm = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
sharedSecret = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"

spec :: Spec
spec = do
    describe "DHKEM through crypton's KEM class" $ do
        it "A.1.1: encapsulating with the vector's ephemeral key" $
            case encapsulateWith
                x25519
                (EncodedPublicKey (hex pkRm))
                (EncodedSecretKey (hex skEm)) of
                CryptoFailed e -> expectationFailure (show e)
                CryptoPassed (EncodedPublicKey enc, ss) -> do
                    enc `shouldBe` hex pkEm
                    (convert ss :: ByteString) `shouldBe` hex sharedSecret

        it "A.1.1: the receiver recovers that secret" $
            case decapsulate
                x25519
                (EncodedSecretKey (hex skRm))
                (EncodedPublicKey (hex pkEm)) of
                CryptoFailed e -> expectationFailure (show e)
                CryptoPassed ss ->
                    (convert ss :: ByteString) `shouldBe` hex sharedSecret

        it "a generated X25519 pair encapsulates and decapsulates" $
            roundTrip x25519

        it "a generated P-256 pair encapsulates and decapsulates" $
            roundTrip p256

        it "the authenticated mode binds the sender's public key" $ do
            (pkS, skS) <- generateKeyPair x25519
            (pkR, skR) <- generateKeyPair x25519
            (pkOther, _) <- generateKeyPair x25519
            skE <- generateCoins x25519
            case authEncapWith x25519 skS pkR skE of
                Left e -> expectationFailure (show e)
                Right (enc, ss) -> do
                    -- the receiver has the sender's public key, not its
                    -- secret one, which is the whole point of the argument
                    authDecap x25519 pkS skR enc `shouldBe` Right ss
                    authDecap x25519 pkOther skR enc `shouldNotBe` Right ss

        it "refuses an encapsulated value that is not a point" $ do
            (_, sk) <- generateKeyPair x25519
            case decapsulate x25519 sk (EncodedPublicKey "short") of
                CryptoPassed _ -> expectationFailure "a 5-byte point was accepted"
                CryptoFailed _ -> return ()

roundTrip
    :: ( KEM kem
       , EncapsulationKey kem ~ EncodedPublicKey
       , DecapsulationKey kem ~ EncodedSecretKey
       , Ciphertext kem ~ EncodedPublicKey
       )
    => Proxy kem -> Expectation
roundTrip p = do
    (pk, sk) <- generateKeyPair p
    r <- encapsulate p pk
    case r of
        CryptoFailed e -> expectationFailure (show e)
        CryptoPassed (enc, ss) -> case decapsulate p sk enc of
            CryptoFailed e -> expectationFailure (show e)
            CryptoPassed ss' ->
                (convert ss' :: ByteString) `shouldBe` convert ss
