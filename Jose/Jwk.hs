{-# LANGUAGE OverloadedStrings, BangPatterns, DeriveGeneric #-}
{-# OPTIONS_HADDOCK prune #-}

module Jose.Jwk
    ( KeyType
    , KeyUse
    , KeyId
    , Jwk (..)
    , JwkSet (..)
    , findMatchingJwsKeys
    , findMatchingJweKeys
    )
where

import           Control.Applicative (pure)
import qualified Crypto.PubKey.RSA as RSA
import           Crypto.Number.Serialize
import           Data.Aeson (genericToJSON, Value(..), FromJSON(..), ToJSON(..), withText)
import           Data.Aeson.Types (Parser, Options (..), defaultOptions)
import           Data.ByteString (ByteString)
import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           GHC.Generics (Generic)

import qualified Jose.Internal.Base64 as B64
import           Jose.Jwa
import           Jose.Types (JwsHeader(..), JweHeader(..))

data KeyType = Rsa
             | Ec
             | Oct
               deriving (Eq, Show)

data EcCurve = P_256
             | P_384
             | P_521
               deriving (Eq,Show)

data KeyUse  = Sig
             | Enc
               deriving (Eq,Show)

type KeyId   = Text

data Jwk = RsaPublicJwk  RSA.PublicKey (Maybe KeyId) (Maybe KeyUse) (Maybe Alg)
         | RsaPrivateJwk RSA.PrivateKey (Maybe KeyId) (Maybe KeyUse) (Maybe Alg)
         | SymmetricJwk  ByteString (Maybe KeyId) (Maybe KeyUse) (Maybe Alg)
           deriving (Show)

data JwkSet = JwkSet
    { keys :: [Jwk]
    } deriving (Show, Generic)

canDecodeJws :: JwsAlg -> Jwk -> Bool
canDecodeJws al jwk = case al of
        HS256 -> mustBeSymmetric
        HS384 -> mustBeSymmetric
        HS512 -> mustBeSymmetric
        RS256 -> mustBeRsa
        RS384 -> mustBeRsa
        RS512 -> mustBeRsa
        -- Not yet supported (EC)
        _     -> False
 where
    mustBeRsa       = not mustBeSymmetric
    mustBeSymmetric = case jwk of
        SymmetricJwk _ _ _ _ -> True
        _                    -> False

canDecodeJwe :: JweAlg -> Jwk -> Bool
canDecodeJwe _ jwk = case jwk of    -- JWE
        RsaPrivateJwk _ _ _ _ -> True
        _                     -> False

jwkId :: Jwk -> Maybe KeyId
jwkId key = case key of
    RsaPublicJwk  _ keyId _ _ -> keyId
    RsaPrivateJwk _ keyId _ _ -> keyId
    SymmetricJwk  _ keyId _ _ -> keyId

findKeyById :: [Jwk] -> KeyId -> Maybe Jwk
findKeyById [] _       = Nothing
findKeyById (key:ks) keyId = case jwkId key of
    Nothing -> findKeyById ks keyId
    Just v  -> if v == keyId
                   then Just key
                   else findKeyById ks keyId

-- TODO filter by key use
findMatchingJwsKeys :: [Jwk] -> JwsHeader -> [Jwk]
findMatchingJwsKeys jwks hdr = filter (canDecodeJws (jwsAlg hdr)) $ filterById (jwsKid hdr) jwks

filterById :: Maybe KeyId -> [Jwk] -> [Jwk]
filterById keyId jwks = case keyId of
        Just i  -> maybe jwks (\key -> [key]) $ findKeyById jwks i
        Nothing -> jwks

findMatchingJweKeys :: [Jwk] -> JweHeader -> [Jwk]
findMatchingJweKeys jwks hdr = filter (canDecodeJwe (jweAlg hdr)) $ filterById (jweKid hdr) jwks

newtype JwkBytes = JwkBytes {bytes :: ByteString} deriving (Show)

instance FromJSON KeyType where
    parseJSON = withText "KeyType" $ \t ->
        case t of
          "RSA" -> pure Rsa
          "EC"  -> pure Ec
          "oct" -> pure Oct
          _     -> fail "unsupported key type"

instance ToJSON KeyType where
    toJSON kt = case kt of
                    Rsa -> String "RSA"
                    Ec  -> String "EC"
                    Oct -> String "oct"

instance FromJSON KeyUse where
    parseJSON = withText "KeyUse" $ \t ->
        case t of
          "sig" -> pure Sig
          "enc" -> pure Enc
          _     -> fail "'use' value must be either 'sig' or 'enc'"

instance ToJSON KeyUse where
    toJSON ku = case ku of
                    Sig -> String "sig"
                    Enc -> String "enc"

instance FromJSON EcCurve where
    parseJSON = withText "EcCurve" $ \t ->
        case t of
          "P-256" -> pure P_256
          "P-384" -> pure P_384
          "P-521" -> pure P_521
          _       -> fail "unsupported 'crv' value"

instance ToJSON EcCurve where
    toJSON c =  case c of
                    P_256 -> String "P-256"
                    P_384 -> String "P-384"
                    P_521 -> String "P-521"

instance FromJSON JwkBytes where
    parseJSON = withText "JwkBytes" $ \t ->
        case B64.decode (TE.encodeUtf8 t) of
          Left  _  -> fail "could not base64 decode bytes"
          Right b  -> pure $ JwkBytes b

instance ToJSON JwkBytes where
    toJSON (JwkBytes b) = String . TE.decodeUtf8 $ B64.encode b

instance FromJSON Jwk where
    parseJSON o@(Object _) = do
        jwkData <- parseJSON o :: Parser JwkData
        case (createJwk jwkData) of
            Left  err -> fail err
            Right jwk -> return jwk
    parseJSON _            = fail "Jwk must be a JSON object"

instance ToJSON Jwk where
    toJSON jwk = toJSON $ case jwk of
                   RsaPublicJwk pubKey mId mUse mAlg ->
                      createPubData pubKey mId mUse mAlg
                   RsaPrivateJwk privKey mId mUse mAlg ->
                      let pubData = createPubData (RSA.private_pub privKey) mId mUse mAlg
                      in  pubData
                            { d  = Just . JwkBytes . i2osp $ RSA.private_d privKey
                            , p  = i2b $ RSA.private_p    privKey
                            , q  = i2b $ RSA.private_q    privKey
                            , dp = i2b $ RSA.private_dP   privKey
                            , dq = i2b $ RSA.private_dQ   privKey
                            , qi = i2b $ RSA.private_qinv privKey
                            }
                   SymmetricJwk bs mId mUse mAlg ->
                      defJwk
                            { kty = Oct
                            , k   = Just $ JwkBytes bs
                            , kid = mId
                            , use = mUse
                            , alg = mAlg
                            }
      where
        i2b 0 = Nothing
        i2b i = Just . JwkBytes . i2osp $ i

        createPubData pubKey mId mUse mAlg = defJwk
                              { n   = Just . JwkBytes . i2osp $ RSA.public_n pubKey
                              , e   = Just . JwkBytes . i2osp $ RSA.public_e pubKey
                              , kid = mId
                              , use = mUse
                              , alg = mAlg
                              }
instance ToJSON JwkSet
instance FromJSON JwkSet

aesonOptions :: Options
aesonOptions = defaultOptions { omitNothingFields = True }

data JwkData = J
    { kty :: KeyType
    -- There's probably a better way to parse this
    -- than encoding all the possible key params
    -- but this will do for now.
    , n   :: Maybe JwkBytes
    , e   :: Maybe JwkBytes
    , d   :: Maybe JwkBytes
    , p   :: Maybe JwkBytes
    , q   :: Maybe JwkBytes
    , dp  :: Maybe JwkBytes
    , dq  :: Maybe JwkBytes
    , qi  :: Maybe JwkBytes
    , k   :: Maybe JwkBytes
    , crv :: Maybe EcCurve
    , x   :: Maybe JwkBytes
    , y   :: Maybe JwkBytes
    , use :: Maybe KeyUse
    , alg :: Maybe Alg
    , kid :: Maybe Text
    , x5u :: Maybe Text
    , x5c :: Maybe [Text]
    , x5t :: Maybe Text
    } deriving (Show, Generic)

instance FromJSON JwkData
instance ToJSON   JwkData where
    toJSON = genericToJSON aesonOptions

defJwk :: JwkData
defJwk = J
    { kty = Rsa
    , n   = Nothing
    , e   = Nothing
    , d   = Nothing
    , p   = Nothing
    , q   = Nothing
    , dp  = Nothing
    , dq  = Nothing
    , qi  = Nothing
    , k   = Nothing
    , crv = Nothing
    , x   = Nothing
    , y   = Nothing
    , use = Just Sig
    , alg = Nothing
    , kid = Nothing
    , x5u = Nothing
    , x5c = Nothing
    , x5t = Nothing
    }

createJwk :: JwkData -> Either String Jwk
createJwk kd = case kd of
    J Rsa (Just nb) (Just eb) Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing u a i _ _ _ ->
        return $ RsaPublicJwk (rsaPub nb eb) i u a
    J Rsa (Just nb) (Just eb) (Just db) mp mq mdp mdq mqi Nothing Nothing Nothing Nothing u a i _ _ _ ->
        return $ RsaPrivateJwk (RSA.PrivateKey (rsaPub nb eb) (os2ip $ bytes db) (os2mip mp) (os2mip mq) (os2mip mdp) (os2mip mdq) (os2mip mqi)) i u a
    J Oct Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Just kb) Nothing Nothing Nothing u a i Nothing Nothing Nothing ->
        return $ SymmetricJwk (bytes kb) i u a
    J Ec _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ ->
        Left "Elliptic curve keys are not supported yet"
    _ -> Left "Invalid key data"
  where
    rsaPub  nb eb  = let m  = os2ip $ bytes nb
                         ex = os2ip $ bytes eb
                     in RSA.PublicKey (rsaSize m 1) m ex
    rsaSize m i    = if (2 ^ (i * 8)) > m then i else rsaSize m (i+1)
    os2mip  mb     = maybe 0 (os2ip . bytes) mb

