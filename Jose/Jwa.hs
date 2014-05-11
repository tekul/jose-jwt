{-# LANGUAGE OverloadedStrings #-}

module Jose.Jwa
    ( Alg (..)
    , Enc (..)
    , encName
    )
where

import Control.Applicative (pure)
import Data.Aeson
import Data.Text (Text)
import Data.Maybe (fromJust)
import Data.Tuple (swap)


data Alg = None | HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | RSA1_5 | RSA_OAEP deriving (Eq, Show)

-- TODO: AES_192_CBC_HMAC_SHA_384 ??
data Enc = A128CBC_HS256 | A256CBC_HS512 | A128GCM | A256GCM deriving (Eq, Show)

algs :: [(Text, Alg)]
algs = [("none", None), ("HS256", HS256), ("HS384", HS384), ("HS512", HS512), ("RS256", RS256), ("RS384", RS384), ("RS512", RS512), ("ES256", ES256), ("RSA1_5", RSA1_5), ("RSA-OAEP", RSA_OAEP)]

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

instance FromJSON Enc where
    parseJSON = withText "Enc" $ \t ->
      maybe (fail "Unsupported enc") pure $ lookup t encs

instance ToJSON Enc where
    toJSON = String . encName


