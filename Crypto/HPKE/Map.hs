
-- | Which algorithms this package will run, and under which identifiers.
module Crypto.HPKE.Map (
    HPKEMap (..),
    defaultHPKEMap,
    defaultKEMMap,
) where

import Crypto.HPKE.DHKEM
import Crypto.HPKE.ID
import Crypto.HPKE.KEM
import Crypto.HPKE.Types

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | The five DHKEMs of RFC 9180 section 7.1.  A KEM added here needs
-- instances of 'Crypto.KEM.KEM' and 'HPKEKEM' and nothing else.
defaultKEMMap :: [(KEM_ID, KEMAlg)]
defaultKEMMap =
    [ (DHKEM_P256_HKDF_SHA256,   KEMAlg (Proxy :: Proxy DHKEM_P256))
    , (DHKEM_P384_HKDF_SHA384,   KEMAlg (Proxy :: Proxy DHKEM_P384))
    , (DHKEM_P521_HKDF_SHA512,   KEMAlg (Proxy :: Proxy DHKEM_P521))
    , (DHKEM_X25519_HKDF_SHA256, KEMAlg (Proxy :: Proxy DHKEM_X25519))
    , (DHKEM_X448_HKDF_SHA512,   KEMAlg (Proxy :: Proxy DHKEM_X448))
    ]
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

data HPKEMap = HPKEMap
    { kemMap :: [(KEM_ID, KEMAlg)]
    , kdfMap :: [(KDF_ID, KDFHash)]
    , cipherMap :: [(AEAD_ID, AEADCipher)]
    }

defaultHPKEMap :: HPKEMap
defaultHPKEMap =
    HPKEMap
        { kemMap = defaultKEMMap
        , kdfMap = defaultKDFMap
        , cipherMap = defaultAEADMap
        }
