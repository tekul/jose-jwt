{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
{-# OPTIONS_HADDOCK prune #-}

module Jose.Types
    ( Jwt (..)
    , Jwe
    , Jws
    , JwtClaims (..)
    , JwtHeader (..)
    , JwsHeader (..)
    , JweHeader (..)
    , JwtError (..)
    , IntDate (..)
    , parseHeader
    , encodeHeader
    , defJwsHdr
    , defJweHdr
    )
where

import Control.Applicative
import Data.Aeson
import Data.Aeson.Types
import Data.Char (toUpper, toLower)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.HashMap.Strict as H
import Data.Int (Int64)
import Data.Time.Clock.POSIX
import Data.Text (Text)
import Data.Vector (singleton)
import GHC.Generics

import Jose.Jwa (JweAlg(..), JwsAlg (..), Enc(..))

-- | The header and claims of a decoded JWS.
type Jws = (JwsHeader, ByteString)

-- | The header and claims of a decoded JWE.
type Jwe = (JweHeader, ByteString)

-- | A decoded JWT which can be either a JWE or a JWS.
data Jwt = Jws !Jws | Jwe !Jwe deriving (Show, Eq)

data JwtHeader = JweH JweHeader
               | JwsH JwsHeader
                 deriving (Show)


-- | Header content for a JWS.
data JwsHeader = JwsHeader {
    jwsAlg :: JwsAlg
  , jwsTyp :: Maybe Text
  , jwsCty :: Maybe Text
  , jwsKid :: Maybe Text
  } deriving (Eq, Show, Generic)

-- | Header content for a JWE.
data JweHeader = JweHeader {
    jweAlg :: JweAlg
  , jweEnc :: Enc
  , jweTyp :: Maybe Text
  , jweCty :: Maybe Text
  , jweZip :: Maybe Text
  , jweKid :: Maybe Text
  } deriving (Eq, Show, Generic)

newtype IntDate = IntDate POSIXTime deriving (Show, Eq, Ord)

instance FromJSON IntDate where
    parseJSON = withScientific "IntDate" $ \n ->
        pure . IntDate . fromIntegral $ (round n :: Int64)

instance ToJSON IntDate where
    toJSON (IntDate t) = Number $ fromIntegral (round t :: Int64)

-- | Registered claims defined in section 4 of the JWT spec.
data JwtClaims = JwtClaims
    { jwtIss :: !(Maybe Text)
    , jwtSub :: !(Maybe Text)
    , jwtAud :: !(Maybe [Text])
    , jwtExp :: !(Maybe IntDate)
    , jwtNbf :: !(Maybe IntDate)
    , jwtIat :: !(Maybe IntDate)
    , jwtJti :: !(Maybe Text)
    } deriving (Show, Generic)

-- Deal with the case where "aud" may be a single value rather than an array
instance FromJSON JwtClaims where
    parseJSON v@(Object o) = case H.lookup "aud" o of
        Just (a@(String _)) -> genericParseJSON claimsOptions $ Object $ H.insert "aud" (Array $ singleton a) o
        _                   -> genericParseJSON claimsOptions v
    parseJSON _            = fail "JwtClaims must be an object"

instance ToJSON JwtClaims where
    toJSON = genericToJSON claimsOptions

claimsOptions :: Options
claimsOptions = prefixOptions "jwt"

defJwsHdr :: JwsHeader
defJwsHdr = JwsHeader None Nothing Nothing Nothing

defJweHdr :: JweHeader
defJweHdr = JweHeader RSA_OAEP A128GCM Nothing Nothing Nothing Nothing

-- | Decoding errors.
data JwtError = KeyError Text      -- ^ No suitable key or wrong key type
              | BadDots Int        -- ^ Wrong number of "." characters in the JWT
              | BadHeader          -- ^ Header couldn't be decoded or contains bad data
              | BadClaims          -- ^ Claims part couldn't be decoded or contains bad data
              | BadSignature       -- ^ Signature is invalid
              | BadCrypto          -- ^ A cryptographic operation failed
              | Base64Error String -- ^ A base64 decoding error
                deriving (Eq, Show)

instance ToJSON JwsHeader where
    toJSON = genericToJSON jwsOptions

instance FromJSON JwsHeader where
    parseJSON = genericParseJSON jwsOptions

instance ToJSON JweHeader where
    toJSON = genericToJSON jweOptions

instance FromJSON JweHeader where
    parseJSON = genericParseJSON jweOptions

instance FromJSON JwtHeader where
    parseJSON v@(Object o) = case H.lookup "enc" o of
        Nothing -> JwsH <$> parseJSON v
        _       -> JweH <$> parseJSON v
    parseJSON _            = fail "JwtHeader must be an object"

encodeHeader :: ToJSON a => a -> ByteString
encodeHeader h = BL.toStrict $ encode h

parseHeader :: ByteString -> Either JwtError JwtHeader
parseHeader hdr = maybe (Left BadHeader) Right $ decodeStrict hdr

jwsOptions :: Options
jwsOptions = prefixOptions "jws"

jweOptions :: Options
jweOptions = prefixOptions "jwe"

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
