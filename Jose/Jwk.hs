{-# LANGUAGE OverloadedStrings, DeriveGeneric, RecordWildCards #-}
{-# OPTIONS_HADDOCK prune #-}

module Jose.Jwk
    ( EcCurve (..)
    , KeyUse (..)
    , KeyId
    , Jwk (..)
    , JwkSet (..)
    , isPublic
    , isPrivate
    , jwkId
    , jwkUse
    , canDecodeJws
    , canDecodeJwe
    , canEncodeJws
    , canEncodeJwe
    , generateRsaKeyPair
    , generateSymmetricKey
    )
where

import           Control.Applicative (pure)
import           Control.Monad (unless)
import           Crypto.Random (MonadRandom, getRandomBytes)
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Types as ECC
import           Crypto.Number.Serialize
import           Data.Aeson (genericToJSON, Value(..), FromJSON(..), ToJSON(..), withText)
import           Data.Aeson.Types (Parser, Options (..), defaultOptions)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Maybe (isNothing)
import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           GHC.Generics (Generic)

import qualified Jose.Internal.Base64 as B64
import           Jose.Jwa
import           Jose.Types (KeyId, JwsHeader(..), JweHeader(..))

data KeyType = Rsa
             | Ec
             | Oct
               deriving (Eq)

data EcCurve = P_256
             | P_384
             | P_521
               deriving (Eq,Show)

data KeyUse  = Sig
             | Enc
               deriving (Eq,Show)

data Jwk = RsaPublicJwk  !RSA.PublicKey   !(Maybe KeyId) !(Maybe KeyUse) !(Maybe Alg)
         | RsaPrivateJwk !RSA.PrivateKey  !(Maybe KeyId) !(Maybe KeyUse) !(Maybe Alg)
         | EcPublicJwk   !ECDSA.PublicKey !(Maybe KeyId) !(Maybe KeyUse) !(Maybe Alg) !EcCurve
         | EcPrivateJwk  !ECDSA.KeyPair   !(Maybe KeyId) !(Maybe KeyUse) !(Maybe Alg) !EcCurve
         | SymmetricJwk  !ByteString      !(Maybe KeyId) !(Maybe KeyUse) !(Maybe Alg)
           deriving (Show, Eq)

data JwkSet = JwkSet
    { keys :: [Jwk]
    } deriving (Show, Eq, Generic)

generateRsaKeyPair :: (MonadRandom m)
    => Int
    -> KeyId
    -> KeyUse
    -> Maybe Alg
    -> m (Jwk, Jwk)
generateRsaKeyPair nBytes id' kuse kalg = do
    (kPub, kPr) <- RSA.generate nBytes 65537
    return (RsaPublicJwk kPub (Just id') (Just kuse) kalg, RsaPrivateJwk kPr (Just id') (Just kuse) kalg)

generateSymmetricKey :: (MonadRandom m)
    => Int
    -> KeyId
    -> KeyUse
    -> Maybe Alg
    -> m Jwk
generateSymmetricKey size id' kuse kalg = do
    k <- getRandomBytes size
    return $ SymmetricJwk k (Just id') (Just kuse) kalg

isPublic :: Jwk -> Bool
isPublic RsaPublicJwk {} = True
isPublic EcPublicJwk  {} = True
isPublic _ = False

isPrivate :: Jwk -> Bool
isPrivate RsaPrivateJwk {} = True
isPrivate EcPrivateJwk  {} = True
isPrivate _ = False

canDecodeJws :: JwsHeader -> Jwk -> Bool
canDecodeJws hdr jwk = jwkUse jwk /= Just Enc &&
    keyIdCompatible (jwsKid hdr) jwk &&
    algCompatible (Signed (jwsAlg hdr)) jwk &&
    case (jwsAlg hdr, jwk) of
        (RS256, RsaPublicJwk {}) -> True
        (RS384, RsaPublicJwk {}) -> True
        (RS512, RsaPublicJwk {}) -> True
        (RS256, RsaPrivateJwk {}) -> True
        (RS384, RsaPrivateJwk {}) -> True
        (RS512, RsaPrivateJwk {}) -> True
        (HS256, SymmetricJwk {}) -> True
        (HS384, SymmetricJwk {}) -> True
        (HS512, SymmetricJwk {}) -> True
        (ES256, EcPublicJwk {})  -> True
        (ES384, EcPublicJwk {})  -> True
        (ES512, EcPublicJwk {})  -> True
        (ES256, EcPrivateJwk {})  -> True
        (ES384, EcPrivateJwk {})  -> True
        (ES512, EcPrivateJwk {})  -> True
        _                        -> False

canEncodeJws :: JwsAlg -> Jwk -> Bool
canEncodeJws a jwk = jwkUse jwk /= Just Enc &&
    algCompatible (Signed a) jwk &&
    case (a, jwk) of
        (RS256, RsaPrivateJwk {}) -> True
        (RS384, RsaPrivateJwk {}) -> True
        (RS512, RsaPrivateJwk {}) -> True
        (HS256, SymmetricJwk {})  -> True
        (HS384, SymmetricJwk {})  -> True
        (HS512, SymmetricJwk {})  -> True
        (ES256, EcPrivateJwk {})  -> True
        (ES384, EcPrivateJwk {})  -> True
        (ES512, EcPrivateJwk {})  -> True
        _                         -> False

canDecodeJwe :: JweHeader -> Jwk -> Bool
canDecodeJwe hdr jwk = jwkUse jwk /= Just Sig &&
    keyIdCompatible (jweKid hdr) jwk &&
    algCompatible (Encrypted (jweAlg hdr)) jwk &&
    case (jweAlg hdr, jwk) of
        (RSA1_5,   RsaPrivateJwk {}) -> True
        (RSA_OAEP, RsaPrivateJwk {}) -> True
        (A128KW,   SymmetricJwk k _ _ _) -> B.length k == 16
        (A192KW,   SymmetricJwk k _ _ _) -> B.length k == 24
        (A256KW,   SymmetricJwk k _ _ _) -> B.length k == 32
        _                            -> False

canEncodeJwe :: JweAlg -> Jwk -> Bool
canEncodeJwe a jwk = jwkUse jwk /= Just Sig &&
    algCompatible (Encrypted a) jwk &&
    case (a, jwk) of
        (RSA1_5,   RsaPublicJwk {})  -> True
        (RSA_OAEP, RsaPublicJwk {})  -> True
        (RSA1_5,   RsaPrivateJwk {}) -> True
        (RSA_OAEP, RsaPrivateJwk {}) -> True
        (A128KW,   SymmetricJwk k _ _ _) -> B.length k == 16
        (A192KW,   SymmetricJwk k _ _ _) -> B.length k == 24
        (A256KW,   SymmetricJwk k _ _ _) -> B.length k == 32
        _                            -> False

keyIdCompatible :: Maybe KeyId -> Jwk -> Bool
keyIdCompatible Nothing _ = True
keyIdCompatible id' jwk   = id' == jwkId jwk

algCompatible :: Alg -> Jwk -> Bool
algCompatible a k' = case jwkAlg k' of
    Nothing -> True
    Just ka -> a == ka

curve :: EcCurve -> ECC.Curve
curve c = ECC.getCurveByName $ case c of
    P_256 -> ECC.SEC_p256r1
    P_384 -> ECC.SEC_p384r1
    P_521 -> ECC.SEC_p521r1

jwkId :: Jwk -> Maybe KeyId
jwkId key = case key of
    RsaPublicJwk  _ keyId _ _ -> keyId
    RsaPrivateJwk _ keyId _ _ -> keyId
    EcPublicJwk   _ keyId _ _ _ -> keyId
    EcPrivateJwk  _ keyId _ _ _ -> keyId
    SymmetricJwk  _ keyId _ _ -> keyId

jwkUse :: Jwk -> Maybe KeyUse
jwkUse key = case key of
    RsaPublicJwk  _ _ u _ -> u
    RsaPrivateJwk _ _ u _ -> u
    EcPublicJwk   _ _ u _ _ -> u
    EcPrivateJwk  _ _ u _ _ -> u
    SymmetricJwk  _ _ u _ -> u

jwkAlg :: Jwk -> Maybe Alg
jwkAlg key = case key of
    RsaPublicJwk  _ _ _ a -> a
    RsaPrivateJwk _ _ _ a -> a
    EcPublicJwk   _ _ _ a _ -> a
    EcPrivateJwk  _ _ _ a _ -> a
    SymmetricJwk  _ _ _ a -> a



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
        case createJwk jwkData of
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
        SymmetricJwk bs mId mUse mAlg -> defJwk
            { kty = Oct
            , k   = Just $ JwkBytes bs
            , kid = mId
            , use = mUse
            , alg = mAlg
            }

        EcPublicJwk pubKey mId mUse mAlg c -> defJwk
            { kty = Ec
            , x   = fst (ecPoint pubKey)
            , y   = snd (ecPoint pubKey)
            , kid = mId
            , use = mUse
            , alg = mAlg
            , crv = Just c
            }

        EcPrivateJwk kp mId mUse mAlg c -> defJwk
            { kty = Ec
            , x   = fst (ecPoint (ECDSA.toPublicKey kp))
            , y   = snd (ecPoint (ECDSA.toPublicKey kp))
            , d   = i2b (ECDSA.private_d (ECDSA.toPrivateKey kp))
            , kid = mId
            , use = mUse
            , alg = mAlg
            , crv = Just c
            }
      where
        i2b 0 = Nothing
        i2b i = Just . JwkBytes . i2osp $ i
        ecPoint pk = case ECDSA.public_q pk of
            ECC.Point xi yi -> (i2b xi, i2b yi)
            _             -> (Nothing, Nothing)

        createPubData pubKey mId mUse mAlg = defJwk
                              { n   = i2b (RSA.public_n pubKey)
                              , e   = i2b (RSA.public_e pubKey)
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
    , kid :: Maybe KeyId
    , x5u :: Maybe Text
    , x5c :: Maybe [Text]
    , x5t :: Maybe Text
    } deriving (Generic)

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
createJwk J {..} = case kty of
    Rsa -> do
        nb <- note "n is required for an RSA key" n
        eb <- note "e is required for an RSA key" e
        checkNoEc
        let kPub = rsaPub nb eb
        case d of
            Nothing -> do
                unless (isNothing (sequence [p, q, dp, dq, qi])) (Left "RSA private parameters can't be set for a public key")
                return (RsaPublicJwk kPub kid use alg)
            Just db -> return $ RsaPrivateJwk (RSA.PrivateKey kPub (os2ip (bytes db)) (os2mip p) (os2mip q) (os2mip dp) (os2mip dq) (os2mip qi)) kid use alg
    Oct -> do
        kb <- note "k is required for a symmetric key" k
        unless (isNothing (sequence [n, e, d, p, q, dp, dq, qi])) (Left "RSA parameters can't be set for a symmetric key")
        checkNoEc
        return $ SymmetricJwk (bytes kb) kid use alg
    Ec  -> do
        crv' <- note "crv is required for an elliptic curve key" crv
        let c = curve crv'
        ecPt <- ecPoint
        unless (isNothing (sequence [n, e, p, q, dp, dq, qi])) (Left "RSA parameters can't be set for an elliptic curve key")
        case d of
            Nothing -> return $ EcPublicJwk (ECDSA.PublicKey c ecPt) kid use alg crv'
            Just db -> return $ EcPrivateJwk (ECDSA.KeyPair c ecPt (os2ip (bytes db))) kid use alg crv'
  where
    checkNoEc = unless (isNothing crv) (Left "Elliptic curve type can't be set for an RSA key") >>
       unless (isNothing (sequence [x, y])) (Left "Elliptic curve coordinates can't be set for an RSA key")
    note err      = maybe (Left err) Right
    os2mip        = maybe 0 (os2ip . bytes)
    rsaPub nb eb  = let m  = os2ip $ bytes nb
                        ex = os2ip $ bytes eb
                    in RSA.PublicKey (rsaSize m 1) m ex
    rsaSize m i   = if (2 ^ (i * 8)) > m then i else rsaSize m (i+1)
    ecPoint       = do
        xb <- note "x is required for an EC key" x
        yb <- note "y is required for an EC key" y
        return $ ECC.Point (os2ip (bytes xb)) (os2ip (bytes yb))
