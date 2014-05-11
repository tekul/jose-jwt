{-# LANGUAGE OverloadedStrings #-}

module Jose.Types
    ( Jwt
    , JwtHeader (..)
    , JwtError (..)
    , parseHeader
    , encodeHeader
    , defHdr
    )
where

import Control.Applicative ((<$>), (<*>))
import Data.Aeson as Aeson
import Data.Aeson.Types
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)

import Jose.Jwa (Alg (..), Enc)

type Jwt = (JwtHeader, ByteString)

data JwtHeader = JwtHeader {
    alg :: Alg
  , enc :: Maybe Enc
  , typ :: Maybe Text
  , cty :: Maybe Text
  } deriving (Eq, Show)

defHdr :: JwtHeader
defHdr = JwtHeader None Nothing Nothing Nothing

data JwtError = Empty | BadDots Int | BadHeader | BadSignature | BadCrypto | Base64Error String
    deriving (Eq, Show)

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
    parseJSON _          = fail "JWT header must be a JSON object"


encodeHeader :: JwtHeader -> ByteString
encodeHeader = B.concat . BL.toChunks . Aeson.encode

parseHeader :: ByteString -> Either JwtError JwtHeader
parseHeader hdr = maybe (Left BadHeader) Right $ Aeson.decode $ BL.fromChunks [hdr]


