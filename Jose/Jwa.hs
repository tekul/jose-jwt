{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_HADDOCK prune #-}

module Jose.Jwa
    ( Alg (..)
    , JwsAlg (..)
    , JweAlg (..)
    , Enc (..)
    , encName
    )
where

import Control.Applicative (pure)
import Data.Aeson
import Data.Text (Text)
import Data.Maybe (fromJust)
import Data.Tuple (swap)

-- | General representation of the @alg@ JWT header value.
data Alg = Signed JwsAlg | Encrypted JweAlg deriving (Eq, Show)

-- | A subset of the signature algorithms from the
-- <http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31#section-3 JWA Spec>.
data JwsAlg = None | HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512 deriving (Eq, Show, Read)

-- | A subset of the key management algorithms from the
-- <http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31#section-5 JWA Spec>.
data JweAlg = RSA1_5 | RSA_OAEP deriving (Eq, Show, Read)

-- | Content encryption algorithms from the
-- <http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31#section-5 JWA Spec>.
-- The optional algorithms A192CBC-HS384 and A192GCM are not supported yet.
data Enc = A128CBC_HS256 | A256CBC_HS512 | A128GCM | A256GCM deriving (Eq, Show)

algs :: [(Text, Alg)]
algs = [("none", Signed None), ("HS256", Signed HS256), ("HS384", Signed HS384), ("HS512", Signed HS512), ("RS256", Signed RS256), ("RS384", Signed RS384), ("RS512", Signed RS512), ("ES256", Signed ES256), ("ES384", Signed ES384), ("ES512", Signed ES512), ("RSA1_5", Encrypted RSA1_5), ("RSA-OAEP", Encrypted RSA_OAEP)]

algName :: Alg -> Text
algName a = fromJust $ lookup a algNames

algNames :: [(Alg, Text)]
algNames = map swap algs

encs :: [(Text, Enc)]
encs = [("A128CBC-HS256", A128CBC_HS256), ("A256CBC-HS512", A256CBC_HS512), ("A128GCM", A128GCM), ("A256GCM", A256GCM)]

encName :: Enc -> Text
encName e = fromJust $ lookup e encNames

encNames :: [(Enc, Text)]
encNames = map swap encs

instance FromJSON Alg where
    parseJSON = withText "Alg" $ \t ->
      maybe (fail "Unsupported alg") pure $ lookup t algs

instance ToJSON Alg where
    toJSON = String . algName

instance FromJSON JwsAlg where
    parseJSON = withText "JwsAlg" $ \t -> case lookup t algs of
        Just (Signed a) -> pure a
        _               -> fail "Unsupported JWS algorithm"

instance ToJSON JwsAlg where
    toJSON a = String . algName $ Signed a

instance FromJSON JweAlg where
    parseJSON = withText "JweAlg" $ \t -> case lookup t algs of
        Just (Encrypted a) -> pure a
        _                  -> fail "Unsupported JWE algorithm"

instance ToJSON JweAlg where
    toJSON a = String . algName $ Encrypted a

instance FromJSON Enc where
    parseJSON = withText "Enc" $ \t ->
      maybe (fail "Unsupported enc") pure $ lookup t encs

instance ToJSON Enc where
    toJSON = String . encName

