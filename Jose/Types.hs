{-# LANGUAGE OverloadedStrings, DeriveGeneric, FlexibleContexts #-}
{-# OPTIONS_HADDOCK prune #-}

module Jose.Types
    ( Jwt (..)
    , Jwe
    , Jws
    , JwtClaims (..)
    , JwtHeader (..)
    , JwsHeader (..)
    , JweHeader (..)
    , JwtContent (..)
    , JwtEncoding (..)
    , JwtError (..)
    , IntDate (..)
    , Payload (..)
    , KeyId (..)
    , parseHeader
    , encodeHeader
    , defJwsHdr
    , defJweHdr
    )
where

import Data.Aeson
import Data.Char (toUpper, toLower)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.HashMap.Strict as H
import Data.Int (Int64)
import Data.Time.Clock (UTCTime)
import Data.Time.Clock.POSIX
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Vector (singleton)
import GHC.Generics

import Jose.Jwa (JweAlg(..), JwsAlg (..), Enc(..))

-- | An encoded JWT.
newtype Jwt = Jwt { unJwt :: ByteString } deriving (Show, Eq)

-- | The payload to be encoded in a JWT.
data Payload = Nested Jwt
             | Claims ByteString
             deriving (Show, Eq)

-- | The header and claims of a decoded JWS.
type Jws = (JwsHeader, ByteString)

-- | The header and claims of a decoded JWE.
type Jwe = (JweHeader, ByteString)

-- | A decoded JWT which can be either a JWE or a JWS, or an unsecured JWT.
data JwtContent = Unsecured !ByteString | Jws !Jws | Jwe !Jwe deriving (Show, Eq)

-- | Defines the encoding information for a JWT.
--
-- Used for both encoding new JWTs and validating existing ones.
data JwtEncoding
    = JwsEncoding JwsAlg
    | JweEncoding JweAlg Enc
      deriving (Eq, Show)

data JwtHeader = JweH JweHeader
               | JwsH JwsHeader
               | UnsecuredH
                 deriving (Show)

data KeyId
    = KeyId    Text
    | UTCKeyId UTCTime
      deriving (Eq, Show, Ord)

instance ToJSON KeyId
  where
    toJSON (KeyId t)    = toJSON t
    toJSON (UTCKeyId t) = toJSON t

instance FromJSON KeyId
  where
    parseJSON = withText "KeyId" $ \t -> do
        let asTime = fromJSON (String t) :: Result UTCTime
        case asTime of
            Success d -> pure (UTCKeyId d)
            _         -> pure (KeyId t)

-- | Header content for a JWS.
data JwsHeader = JwsHeader {
    jwsAlg :: JwsAlg
  , jwsTyp :: Maybe Text
  , jwsCty :: Maybe Text
  , jwsKid :: Maybe KeyId
  } deriving (Eq, Show, Generic)

-- | Header content for a JWE.
data JweHeader = JweHeader {
    jweAlg :: JweAlg
  , jweEnc :: Enc
  , jweTyp :: Maybe Text
  , jweCty :: Maybe Text
  , jweZip :: Maybe Text
  , jweKid :: Maybe KeyId
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

instance ToJSON Jwt where
    toJSON (Jwt bytes) = String (TE.decodeUtf8 bytes)

instance FromJSON Jwt where
    parseJSON (String token) = pure $ Jwt (TE.encodeUtf8 token)
    parseJSON _              = fail "Jwt must be a string"

claimsOptions :: Options
claimsOptions = prefixOptions "jwt"

defJwsHdr :: JwsHeader
defJwsHdr = JwsHeader RS256 Nothing Nothing Nothing

defJweHdr :: JweHeader
defJweHdr = JweHeader RSA_OAEP A128GCM Nothing Nothing Nothing Nothing

-- | Decoding errors.
data JwtError = KeyError Text      -- ^ No suitable key or wrong key type
              | BadAlgorithm Text  -- ^ The supplied algorithm is invalid
              | BadDots Int        -- ^ Wrong number of "." characters in the JWT
              | BadHeader Text     -- ^ Header couldn't be decoded or contains bad data
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
    parseJSON v@(Object o) = case H.lookup "alg" o of
        Just (String "none") -> pure UnsecuredH
        _                    -> case H.lookup "enc" o of
            Nothing -> JwsH <$> parseJSON v
            _       -> JweH <$> parseJSON v
    parseJSON _            = fail "JwtHeader must be an object"

encodeHeader :: ToJSON a => a -> ByteString
encodeHeader h = BL.toStrict $ encode h

parseHeader :: ByteString -> Either JwtError JwtHeader
parseHeader hdr = either (Left . BadHeader . T.pack) return $ eitherDecodeStrict' hdr

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
