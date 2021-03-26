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
import           Crypto.Error (CryptoFailable(..))
import           Crypto.Random (MonadRandom, getRandomBytes)
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.ECC.Types as ECC
import           Crypto.Number.Serialize
import           Data.Aeson (fromJSON, genericToJSON, Object, Result(..), Value(..), FromJSON(..), ToJSON(..), withText)
import           Data.Aeson.Types (Parser, Options (..), defaultOptions)
import qualified Data.ByteArray as BA
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.HashMap.Strict as H
import           Data.Maybe (isNothing, fromMaybe)
import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           GHC.Generics (Generic)

import qualified Jose.Internal.Base64 as B64
import           Jose.Jwa
import           Jose.Types (KeyId, JwsHeader(..), JweHeader(..))

data KeyType = Rsa
             | Ec
             | Okp
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
         | Ed25519PrivateJwk !Ed25519.SecretKey !Ed25519.PublicKey !(Maybe KeyId)
         | Ed25519PublicJwk !Ed25519.PublicKey !(Maybe KeyId)
         | Ed448PrivateJwk !Ed448.SecretKey !Ed448.PublicKey !(Maybe KeyId)
         | Ed448PublicJwk !Ed448.PublicKey !(Maybe KeyId)
         | SymmetricJwk  !ByteString      !(Maybe KeyId) !(Maybe KeyUse) !(Maybe Alg)
         | UnsupportedJwk Object
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
        (EdDSA, Ed25519PublicJwk {}) -> True
        (EdDSA, Ed25519PrivateJwk {}) -> True
        (EdDSA, Ed448PublicJwk {}) -> True
        (EdDSA, Ed448PrivateJwk {}) -> True
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
        (EdDSA, Ed25519PrivateJwk {}) -> True
        (EdDSA, Ed448PrivateJwk {}) -> True
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
        (RSA1_5,       RsaPrivateJwk {}) -> True
        (RSA_OAEP,     RsaPrivateJwk {}) -> True
        (RSA_OAEP_256, RsaPrivateJwk {}) -> True
        (A128KW,       SymmetricJwk k _ _ _) -> B.length k == 16
        (A192KW,       SymmetricJwk k _ _ _) -> B.length k == 24
        (A256KW,       SymmetricJwk k _ _ _) -> B.length k == 32
        _                            -> False

canEncodeJwe :: JweAlg -> Jwk -> Bool
canEncodeJwe a jwk = jwkUse jwk /= Just Sig &&
    algCompatible (Encrypted a) jwk &&
    case (a, jwk) of
        (RSA1_5,       RsaPublicJwk {})  -> True
        (RSA_OAEP,     RsaPublicJwk {})  -> True
        (RSA_OAEP_256, RsaPublicJwk {})  -> True
        (RSA1_5,       RsaPrivateJwk {}) -> True
        (RSA_OAEP,     RsaPrivateJwk {}) -> True
        (RSA_OAEP_256, RsaPrivateJwk {}) -> True
        (A128KW,       SymmetricJwk k _ _ _) -> B.length k == 16
        (A192KW,       SymmetricJwk k _ _ _) -> B.length k == 24
        (A256KW,       SymmetricJwk k _ _ _) -> B.length k == 32
        _                            -> False

keyIdCompatible :: Maybe KeyId -> Jwk -> Bool
keyIdCompatible Nothing _ = True
keyIdCompatible id' jwk   = id' == jwkId jwk

algCompatible :: Alg -> Jwk -> Bool
algCompatible a k' = case jwkAlg k' of
    Nothing -> True
    Just ka -> a == ka

ecCurve :: Text -> Maybe (EcCurve, ECC.Curve)
ecCurve c = case c of
    "P-256" -> Just (P_256, ECC.getCurveByName ECC.SEC_p256r1)
    "P-384" -> Just (P_384, ECC.getCurveByName ECC.SEC_p384r1)
    "P-521" -> Just (P_521, ECC.getCurveByName ECC.SEC_p521r1)
    _ -> Nothing

ecCurveName :: EcCurve -> Text
ecCurveName c = case c of
    P_256 -> "P-256"
    P_384 -> "P-384"
    P_521 -> "P-521"

jwkId :: Jwk -> Maybe KeyId
jwkId key = case key of
    Ed25519PrivateJwk _ _ keyId -> keyId
    Ed25519PublicJwk _ keyId -> keyId
    Ed448PrivateJwk _ _ keyId -> keyId
    Ed448PublicJwk _ keyId -> keyId
    RsaPublicJwk  _ keyId _ _ -> keyId
    RsaPrivateJwk _ keyId _ _ -> keyId
    EcPublicJwk   _ keyId _ _ _ -> keyId
    EcPrivateJwk  _ keyId _ _ _ -> keyId
    SymmetricJwk  _ keyId _ _ -> keyId
    UnsupportedJwk _ -> Nothing

jwkUse :: Jwk -> Maybe KeyUse
jwkUse key = case key of
    Ed25519PrivateJwk _ _ _ -> Just Sig
    Ed25519PublicJwk _ _ -> Just Sig
    Ed448PrivateJwk _ _ _ -> Just Sig
    Ed448PublicJwk _ _ -> Just Sig
    RsaPublicJwk  _ _ u _ -> u
    RsaPrivateJwk _ _ u _ -> u
    EcPublicJwk   _ _ u _ _ -> u
    EcPrivateJwk  _ _ u _ _ -> u
    SymmetricJwk  _ _ u _ -> u
    UnsupportedJwk _ -> Nothing

jwkAlg :: Jwk -> Maybe Alg
jwkAlg key = case key of
    Ed25519PrivateJwk _ _ _ -> Just (Signed EdDSA)
    Ed25519PublicJwk _ _ -> Just (Signed EdDSA)
    Ed448PrivateJwk _ _ _ -> Just (Signed EdDSA)
    Ed448PublicJwk _ _ -> Just (Signed EdDSA)
    RsaPublicJwk  _ _ _ a -> a
    RsaPrivateJwk _ _ _ a -> a
    EcPublicJwk   _ _ _ a _ -> a
    EcPrivateJwk  _ _ _ a _ -> a
    SymmetricJwk  _ _ _ a -> a
    UnsupportedJwk _ -> Nothing


newtype JwkBytes = JwkBytes {bytes :: ByteString} deriving (Show)

instance FromJSON KeyType where
    parseJSON = withText "KeyType" $ \t ->
        case t of
          "RSA" -> pure Rsa
          "OKP" -> pure Okp
          "EC"  -> pure Ec
          "oct" -> pure Oct
          _     -> fail "unsupported key type"

instance ToJSON KeyType where
    toJSON kt = case kt of
                    Rsa -> String "RSA"
                    Okp -> String "OKP"
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
    parseJSON (Object k) = parseJwk k
    parseJSON _            = fail "Jwk must be a JSON object"

parseJwk :: Object -> Parser Jwk
parseJwk k = do
    case (checkAlg, checkKty) of
        (Success _, Success _) -> do
            jwkData <- parseJSON (Object k) :: Parser JwkData
            case createJwk jwkData of
                Left  err -> fail err
                Right jwk -> return jwk
        _ -> pure (UnsupportedJwk k)
  where
    algValue = fromMaybe Null (H.lookup "alg" k)
    -- kty is required so if it's missing here we do nothing and allow decoding to fail
    -- later
    ktyValue = fromMaybe Null (H.lookup "kty" k)
    checkAlg = fromJSON algValue :: Result (Maybe Alg)
    checkKty = fromJSON ktyValue :: Result (Maybe KeyType)

instance ToJSON Jwk where
    toJSON jwk = case jwk of
        RsaPublicJwk pubKey mId mUse mAlg ->
          toJSON $ createPubData pubKey mId mUse mAlg
        RsaPrivateJwk privKey mId mUse mAlg ->
            let pubData = createPubData (RSA.private_pub privKey) mId mUse mAlg
            in  toJSON $ pubData
                { d  = Just . JwkBytes . i2osp $ RSA.private_d privKey
                , p  = i2b $ RSA.private_p    privKey
                , q  = i2b $ RSA.private_q    privKey
                , dp = i2b $ RSA.private_dP   privKey
                , dq = i2b $ RSA.private_dQ   privKey
                , qi = i2b $ RSA.private_qinv privKey
                }

        Ed25519PrivateJwk kPr kPub kid_ -> toJSON $ defJwk
            { kty = Okp
            , crv = Just "Ed25519"
            , d = Just (JwkBytes (BA.convert kPr))
            , x = Just (JwkBytes (BA.convert kPub))
            , kid = kid_
            }

        Ed25519PublicJwk kPub kid_ -> toJSON $ defJwk
            { kty = Okp
            , crv = Just "Ed25519"
            , x = Just (JwkBytes (BA.convert kPub))
            , kid = kid_
            }

        Ed448PrivateJwk kPr kPub kid_ -> toJSON $ defJwk
            { kty = Okp
            , crv = Just "Ed448"
            , d = Just (JwkBytes (BA.convert kPr))
            , x = Just (JwkBytes (BA.convert kPub))
            , kid = kid_
            }

        Ed448PublicJwk kPub kid_ -> toJSON $ defJwk
            { kty = Okp
            , crv = Just "Ed448"
            , x = Just (JwkBytes (BA.convert kPub))
            , kid = kid_
            }


        SymmetricJwk bs mId mUse mAlg -> toJSON $ defJwk
            { kty = Oct
            , k   = Just $ JwkBytes bs
            , kid = mId
            , use = mUse
            , alg = mAlg
            }

        EcPublicJwk pubKey mId mUse mAlg c -> toJSON $ defJwk
            { kty = Ec
            , x   = fst (ecPoint pubKey)
            , y   = snd (ecPoint pubKey)
            , kid = mId
            , use = mUse
            , alg = mAlg
            , crv = Just (ecCurveName c)
            }

        EcPrivateJwk kp mId mUse mAlg c -> toJSON $ defJwk
            { kty = Ec
            , x   = fst (ecPoint (ECDSA.toPublicKey kp))
            , y   = snd (ecPoint (ECDSA.toPublicKey kp))
            , d   = i2b (ECDSA.private_d (ECDSA.toPrivateKey kp))
            , kid = mId
            , use = mUse
            , alg = mAlg
            , crv = Just (ecCurveName c)
            }

        UnsupportedJwk k -> Object k
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
    , crv :: Maybe Text
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
    Okp -> do
        crv' <- note "crv is required for an OKP key" crv
        x' <- note "x is required for an OKP key" x
        unless (isNothing (sequence [n, e, p, q, dp, dq, qi])) (Left "RSA parameters can't be set for an OKP key")
        case crv' of
          "Ed25519" -> case d of
              Just db -> do
                  secKey <- createOkpKey Ed25519.secretKey (bytes db)
                  pubKey <- createOkpKey Ed25519.publicKey (bytes x')
                  unless (pubKey == Ed25519.toPublic secKey) (Left "Public key x doesn't match private key d")
                  return (Ed25519PrivateJwk secKey pubKey kid)
              Nothing -> do
                  pubKey <- createOkpKey Ed25519.publicKey (bytes x')
                  return (Ed25519PublicJwk pubKey kid)
          "Ed448" -> case d of
              Just db -> do
                  secKey <- createOkpKey Ed448.secretKey (bytes db)
                  pubKey <- createOkpKey Ed448.publicKey (bytes x')
                  unless (pubKey == Ed448.toPublic secKey) (Left "Public key x doesn't match private key d")
                  return (Ed448PrivateJwk secKey pubKey kid)
              Nothing -> do
                  pubKey <- createOkpKey Ed448.publicKey (bytes x')
                  return (Ed448PublicJwk pubKey kid)

          _ -> Left "Unknown or unsupported OKP type"
    Ec  -> do
        crv' <- note "crv is required for an elliptic curve key" crv
        (crv'', c) <- note "crv must be a valid EC curve name" (ecCurve crv')
        ecPt <- ecPoint
        unless (isNothing (sequence [n, e, p, q, dp, dq, qi])) (Left "RSA parameters can't be set for an elliptic curve key")
        case d of
            Nothing -> return $ EcPublicJwk (ECDSA.PublicKey c ecPt) kid use alg crv''
            Just db -> return $ EcPrivateJwk (ECDSA.KeyPair c ecPt (os2ip (bytes db))) kid use alg crv''
  where
    checkNoEc = unless (isNothing crv) (Left "Elliptic curve type can't be set for an RSA key") >>
       unless (isNothing (sequence [x, y])) (Left "Elliptic curve coordinates can't be set for an RSA key")
    createOkpKey f ba = case f ba of
       CryptoPassed k_ -> Right k_
       _ -> Left "Invalid OKP key data"

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
