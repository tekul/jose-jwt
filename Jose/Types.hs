{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Jose.Types
    ( Jwt
    , JwtHeader (..)
    , JwtError (..)
    , parseHeader
    , encodeHeader
    , defHdr
    )
where

import Data.Aeson as Aeson
import Data.Aeson.Types
import Data.Char (toUpper, toLower)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import GHC.Generics
import Data.Text (Text)

import Jose.Jwa (Alg (..), Enc)

type Jwt = (JwtHeader, ByteString)

data JwtHeader = JwtHeader {
    jwtAlg :: Alg
  , jwtEnc :: Maybe Enc
  , jwtTyp :: Maybe Text
  , jwtCty :: Maybe Text
  , jwtZip :: Maybe Text
  , jwtKid :: Maybe Text
  } deriving (Eq, Show, Generic)

defHdr :: JwtHeader
defHdr = JwtHeader None Nothing Nothing Nothing Nothing Nothing

data JwtError = Empty | KeyError Text | BadDots Int | BadHeader | BadSignature | BadCrypto | Base64Error String
    deriving (Eq, Show)

instance ToJSON JwtHeader where
    toJSON = genericToJSON hdrOptions

instance FromJSON JwtHeader where
    parseJSON = genericParseJSON hdrOptions

encodeHeader :: JwtHeader -> ByteString
encodeHeader = B.concat . BL.toChunks . Aeson.encode

parseHeader :: ByteString -> Either JwtError JwtHeader
parseHeader hdr = maybe (Left BadHeader) Right $ Aeson.decode $ BL.fromChunks [hdr]

hdrOptions :: Options
hdrOptions = prefixOptions "jwt"

prefixOptions :: String -> Options
prefixOptions prefix = omitNothingOptions
    { fieldLabelModifier     = dropPrefix $ length prefix
    , constructorTagModifier = addPrefix prefix
    }
  where
    omitNothingOptions = defaultOptions { omitNothingFields = True }
    dropPrefix l s = let remainder = drop l s
                     in  (toLower . head) remainder : tail remainder

    addPrefix p s  = p ++ toUpper (head s) : tail s
