{-# LANGUAGE OverloadedStrings #-}

module Data.Jwt.Types
    ( Alg (..)
    , Enc (..)
    , Jwt
    , JwtHeader (..)
    , JwtError (..)
    , encName
    )
where

import Control.Applicative ((<$>), (<*>), pure)
import Data.Aeson as Aeson
import Data.Aeson.Types
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Maybe (fromJust)
import Data.Tuple (swap)

type Jwt = (JwtHeader, ByteString)

data JwtHeader = JwtHeader {
    alg :: Alg
  , enc :: Maybe Enc
  , typ :: Maybe Text
  , cty :: Maybe Text
  } deriving (Eq, Show)

data JwtError = Empty | BadDots Int | BadHeader | BadSignature | BadCrypto | Base64Error String
    deriving (Eq, Show)

data Alg = None | HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | RSA1_5 | RSA_OAEP deriving (Eq, Show)

data Enc = A128CBC_HS256 | A256CBC_HS512 | A128GCM | A256GCM deriving (Eq, Show)

algs = [("none",None), ("HS256",HS256), ("HS384",HS384), ("HS512",HS512), ("RS256",RS256), ("RS384",RS384),("RS512",RS512),("ES256",ES256), ("RSA1_5",RSA1_5),("RSA-OAEP",RSA_OAEP)]

algName a = fromJust $ lookup a algNames

algNames = map swap algs

encs = [("A128CBC-HS256",A128CBC_HS256), ("A256CBC-HS512",A256CBC_HS512), ("A128GCM", A128GCM), ("A256GCM", A256GCM)]

encName e = fromJust $ lookup e encNames

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


instance ToJSON JwtHeader where
    toJSON h = object $ stripNulls [
                        "alg" .= alg h,
                        "enc" .= enc h,
                        "typ" .= typ h,
                        "cty" .= cty h ]

stripNulls :: [Pair] -> [Pair]
stripNulls = filter (\(_,v) -> v /= Null)

instance FromJSON JwtHeader where
    parseJSON (Object v) = JwtHeader <$>
        v .: "alg"                   <*>
        v .:? "enc"                  <*>
        v .:? "typ"                  <*>
        v .:? "cty"


