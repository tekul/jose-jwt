{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
{-# OPTIONS_HADDOCK prune #-}

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

-- | Represents a decoded JWT.
type Jwt = (JwtHeader, ByteString)

-- | Standard header content for a JWT.
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

-- | Decoding errors.
data JwtError = --Empty
                KeyError Text      -- ^ No suitable key or wrong key type
              | BadDots Int        -- ^ Wrong number of "." characters in the JWT
              | BadHeader          -- ^ Header couldn't be decoded or contains bad data
              | BadSignature       -- ^ Signature is invalid
              | BadCrypto          -- ^ A cryptographic operation failed
              | Base64Error String -- ^ A base64 decoding error
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
