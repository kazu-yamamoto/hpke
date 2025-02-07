{-# LANGUAGE OverloadedStrings #-}

module A2Spec where

import Data.ByteString ()
import Test.Hspec

import Crypto.HPKE

spec :: Spec
spec = do
    describe "A.2. DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305" $ do
        it "A.2.1. Base Setup Information" $ do
            let info =
                    "\x4f\x64\x65\x20\x6f\x6e\x20\x61\x20\x47\x72\x65\x63\x69\x61\x6e\x20\x55\x72\x6e"
                pkEm =
                    "\x1a\xfa\x08\xd3\xde\xc0\x47\xa6\x43\x88\x51\x63\xf1\x18\x04\x76\xfa\x7d\xdb\x54\xc6\xa8\x02\x9e\xa3\x3f\x95\x79\x6b\xf2\xac\x4a"
                        :: EncodedPublicKey
                skEm =
                    "\xf4\xec\x9b\x33\xb7\x92\xc3\x72\xc1\xd2\xc2\x06\x35\x07\xb6\x84\xef\x92\x5b\x8c\x75\xa4\x2d\xbc\xbf\x57\xd6\x3c\xcd\x38\x16\x00"
                        :: EncodedSecretKey
                pkRm =
                    "\x43\x10\xee\x97\xd8\x8c\xc1\xf0\x88\xa5\x57\x6c\x77\xab\x0c\xf5\xc3\xac\x79\x7f\x3d\x95\x13\x9c\x6c\x84\xb5\x42\x9c\x59\x66\x2a"
                        :: EncodedPublicKey
                skRm =
                    "\x80\x57\x99\x1e\xef\x8f\x1f\x1a\xf1\x8f\x4a\x94\x91\xd1\x6a\x1c\xe3\x33\xf6\x95\xd4\xdb\x8e\x38\xda\x75\x97\x5c\x44\x78\xe0\xfb"
                        :: EncodedSecretKey
            (enc, ctxS) <-
                setupBaseS
                    DHKEM_X25519_HKDF_SHA256
                    HKDF_SHA256
                    ChaCha20Poly1305
                    (Just skEm)
                    Nothing
                    pkRm
                    info
            ctxR <-
                setupBaseR
                    DHKEM_X25519_HKDF_SHA256
                    HKDF_SHA256
                    ChaCha20Poly1305
                    skRm
                    Nothing
                    pkEm
                    info
            enc `shouldBe` pkEm
            let pt = "Beauty is truth, truth beauty"
                aad0 = "\x43\x6f\x75\x6e\x74\x2d\x30"
                ct0 =
                    "\x1c\x52\x50\xd8\x03\x4e\xc2\xb7\x84\xba\x2c\xfd\x69\xdb\xdb\x8a\xf4\x06\xcf\xe3\xff\x93\x8e\x13\x1f\x0d\xef\x8c\x8b\x60\xb4\xdb\x21\x99\x3c\x62\xce\x81\x88\x3d\x2d\xd1\xb5\x1a\x28"
            ct0' <- seal ctxS aad0 pt
            ct0' `shouldBe` ct0
            pt0 <- open ctxR aad0 ct0
            pt0 `shouldBe` pt
            let aad1 = "\x43\x6f\x75\x6e\x74\x2d\x31"
                ct1 =
                    "\x6b\x53\xc0\x51\xe4\x19\x9c\x51\x8d\xe7\x95\x94\xe1\xc4\xab\x18\xb9\x6f\x08\x15\x49\xd4\x5c\xe0\x15\xbe\x00\x20\x90\xbb\x11\x9e\x85\x28\x53\x37\xcc\x95\xba\x5f\x59\x99\x2d\xc9\x8c"
            ct1' <- seal ctxS aad1 pt
            ct1' `shouldBe` ct1
            pt1 <- open ctxR aad1 ct1
            pt1 `shouldBe` pt

        it "A.2.2. PSK Setup Information" $ do
            let info =
                    "\x4f\x64\x65\x20\x6f\x6e\x20\x61\x20\x47\x72\x65\x63\x69\x61\x6e\x20\x55\x72\x6e"
                pkEm =
                    "\x22\x61\x29\x9c\x3f\x40\xa9\xaf\xc1\x33\xb9\x69\xa9\x7f\x05\xe9\x5b\xe2\xc5\x14\xe5\x4f\x3d\xe2\x6c\xbe\x56\x44\xac\x73\x5b\x04"
                        :: EncodedPublicKey
                skEm =
                    "\x0c\x35\xfd\xf4\x9d\xf7\xaa\x01\xcd\x33\x00\x49\x33\x2c\x40\x41\x1e\xbb\xa3\x6e\x0c\x71\x8e\xbc\x3e\xdf\x58\x45\x79\x5f\x63\x21"
                        :: EncodedSecretKey
                pkRm =
                    "\x13\x64\x0a\xf8\x26\xb7\x22\xfc\x04\xfe\xaa\x4d\xe2\xf2\x8f\xbd\x5e\xcc\x03\x62\x3b\x31\x78\x34\xe7\xff\x41\x20\xdb\xe7\x30\x62"
                        :: EncodedPublicKey
                skRm =
                    "\x77\xd1\x14\xe0\x21\x2b\xe5\x1c\xb1\xd7\x6f\xa9\x9d\xd4\x1c\xfd\x4d\x01\x66\xb0\x8c\xaa\x09\x07\x44\x30\xa6\xc5\x9e\xf1\x78\x79"
                        :: EncodedSecretKey
                psk =
                    "\x02\x47\xfd\x33\xb9\x13\x76\x0f\xa1\xfa\x51\xe1\x89\x2d\x9f\x30\x7f\xbe\x65\xeb\x17\x1e\x81\x32\xc2\xaf\x18\x55\x5a\x73\x8b\x82"
                psk_id =
                    "\x45\x6e\x6e\x79\x6e\x20\x44\x75\x72\x69\x6e\x20\x61\x72\x61\x6e\x20\x4d\x6f\x72\x69\x61"
            (enc, ctxS) <-
                setupPSKS
                    DHKEM_X25519_HKDF_SHA256
                    HKDF_SHA256
                    ChaCha20Poly1305
                    (Just skEm)
                    Nothing
                    pkRm
                    info
                    psk
                    psk_id
            ctxR <-
                setupPSKR
                    DHKEM_X25519_HKDF_SHA256
                    HKDF_SHA256
                    ChaCha20Poly1305
                    skRm
                    Nothing
                    pkEm
                    info
                    psk
                    psk_id
            enc `shouldBe` pkEm
            let pt = "Beauty is truth, truth beauty"
                aad0 = "\x43\x6f\x75\x6e\x74\x2d\x30"
                ct0 =
                    "\x4a\x17\x7f\x9c\x0d\x6f\x15\xcf\xdf\x53\x3f\xb6\x5b\xf8\x4a\xec\xdc\x6a\xb1\x6b\x8b\x85\xb4\xcf\x65\xa3\x70\xe0\x7f\xc1\xd7\x8d\x28\xfb\x07\x32\x14\x52\x52\x76\xf4\xa8\x96\x08\xff"
            ct0' <- seal ctxS aad0 pt
            ct0' `shouldBe` ct0
            pt0 <- open ctxR aad0 ct0
            pt0 `shouldBe` pt
            let aad1 = "\x43\x6f\x75\x6e\x74\x2d\x31"
                ct1 =
                    "\x5c\x3c\xab\xae\x2f\x0b\x3e\x12\x4d\x8d\x86\x4c\x11\x6f\xd8\xf2\x0f\x3f\x56\xfd\xa9\x88\xc3\x57\x3b\x40\xb0\x99\x97\xfd\x6c\x76\x9e\x77\xc8\xed\xa6\xcd\xa4\xf9\x47\xf5\xb7\x04\xa8"
            ct1' <- seal ctxS aad1 pt
            ct1' `shouldBe` ct1
            pt1 <- open ctxR aad1 ct1
            pt1 `shouldBe` pt
