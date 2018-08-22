{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | JWS HMAC and RSA signed token support.
--
-- Example usage with HMAC:
--
-- >>> import Jose.Jws
-- >>> import Jose.Jwa
-- >>> let Right (Jwt jwt) = hmacEncode HS256 "secretmackey" "public claims"
-- >>> jwt
-- "eyJhbGciOiJIUzI1NiJ9.cHVibGljIGNsYWltcw.GDV7RdBrCYfCtFCZZGPy_sWry4GwfX3ckMywXUyxBsc"
-- >>> hmacDecode "wrongkey" jwt
-- Left BadSignature
-- >>> hmacDecode "secretmackey" jwt
-- Right (JwsHeader {jwsAlg = HS256, jwsTyp = Nothing, jwsCty = Nothing, jwsKid = Nothing},"public claims")

module Jose.Jws
    ( jwkEncode
    , hmacEncode
    , hmacDecode
    , rsaEncode
    , rsaDecode
    , ecEncode
    , ecDecode
    )
where

import Crypto.Number.Serialize (os2ip)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Types as ECC
import Crypto.PubKey.RSA (PrivateKey(..), PublicKey(..), generateBlinder)
import Crypto.Random (MonadRandom, getRandomBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Jose.Types
import qualified Jose.Internal.Base64 as B64
import Jose.Internal.Crypto
import qualified Jose.Internal.Parser as P
import Jose.Jwa
import Jose.Jwk (Jwk (..), EcCurve(..))

-- | Create a JWS signed with a JWK.
-- The key and algorithm must be consistent or an error
-- will be returned.
jwkEncode :: MonadRandom m
          => JwsAlg                          -- ^ The algorithm to use
          -> Jwk                             -- ^ The key to sign with
          -> Payload                         -- ^ The public JWT claims
          -> m (Either JwtError Jwt)         -- ^ The encoded token, if successful
jwkEncode a key payload = case key of
    RsaPrivateJwk kPr kid _ _   -> rsaEncodeInternal a kPr (sigTarget a kid payload)
    SymmetricJwk  k   kid _ _   -> return $ hmacEncodeInternal a k (sigTarget a kid payload)
    EcPrivateJwk  kp  kid _ _ c -> 
        let (ECDSA.KeyPair keyCurve _ _) = kp
        in if keyCurve == curve c
            then ecEncodeInternal a kp (sigTarget a kid payload)
            else return . Left $ KeyError "Curve in Cryptonite Key is incompatible with JWK curve"
    _                           -> return $ Left $ BadAlgorithm "EC signing is not supported"
  where
    curve = \case
        P_256 -> ECC.getCurveByName ECC.SEC_p256r1
        P_384 -> ECC.getCurveByName ECC.SEC_p384r1
        P_521 -> ECC.getCurveByName ECC.SEC_p521r1

-- | Create a JWS with an HMAC for validation.
hmacEncode :: JwsAlg       -- ^ The MAC algorithm to use
           -> ByteString   -- ^ The MAC key
           -> ByteString   -- ^ The public JWT claims (token content)
           -> Either JwtError Jwt -- ^ The encoded JWS token
hmacEncode a key payload = hmacEncodeInternal a key (sigTarget a Nothing (Claims payload))

hmacEncodeInternal :: JwsAlg
                   -> ByteString
                   -> ByteString
                   -> Either JwtError Jwt
hmacEncodeInternal a key st = Jwt . (\mac -> B.concat [st, ".", B64.encode mac]) <$> hmacSign a key st

-- | Decodes and validates an HMAC signed JWS.
hmacDecode :: ByteString          -- ^ The HMAC key
           -> ByteString          -- ^ The JWS token to decode
           -> Either JwtError Jws -- ^ The decoded token if successful
hmacDecode key = decode (`hmacVerify` key)

-- | Creates a JWS with an RSA signature.
rsaEncode :: MonadRandom m
          => JwsAlg                           -- ^ The RSA algorithm to use
          -> PrivateKey                       -- ^ The key to sign with
          -> ByteString                       -- ^ The public JWT claims (token content)
          -> m (Either JwtError Jwt)          -- ^ The encoded JWS token
rsaEncode a pk payload = rsaEncodeInternal a pk (sigTarget a Nothing (Claims payload))

rsaEncodeInternal :: MonadRandom m
                  => JwsAlg
                  -> PrivateKey
                  -> ByteString
                  -> m (Either JwtError Jwt)
rsaEncodeInternal a pk st = do
    blinder <- generateBlinder (public_n $ private_pub pk)
    return $ sign blinder
  where
    sign b = case rsaSign (Just b) a pk st of
        Right sig -> Right . Jwt $ B.concat [st, ".", B64.encode sig]
        Left e    -> Left e

-- | Decode and validate an RSA signed JWS.
rsaDecode :: PublicKey            -- ^ The key to check the signature with
          -> ByteString           -- ^ The encoded JWS
          -> Either JwtError Jws  -- ^ The decoded token if successful
rsaDecode key = decode (`rsaVerify` key)

ecEncode :: MonadRandom m
         => JwsAlg
         -> ECDSA.KeyPair
         -> ByteString
         -> m (Either JwtError Jwt)
ecEncode a kp payload = ecEncodeInternal a kp (sigTarget a Nothing (Claims payload))

ecEncodeInternal :: MonadRandom m
                 => JwsAlg
                 -> ECDSA.KeyPair
                 -> ByteString
                 -> m (Either JwtError Jwt)
ecEncodeInternal a kp st = do
    k <- os2ip <$> (getRandomBytes 32 :: MonadRandom m => m ByteString)
    if k >= (ECC.ecc_n . ECC.common_curve $ curve)
        then ecEncodeInternal a kp st
        else return $ case ecSign k a (ECDSA.toPrivateKey kp) st of
            Right sig -> Right . Jwt $ B.concat [st, ".", B64.encode sig]
            Left e -> Left e
  where
    (ECDSA.KeyPair curve _ _) = kp



-- | Decode and validate an EC signed JWS
ecDecode :: ECDSA.PublicKey       -- ^ The key to check the signature with
         -> ByteString            -- ^ The encoded JWS
         -> Either JwtError Jws   -- ^ The decoded token if successful
ecDecode key = decode (`ecVerify` key)

sigTarget :: JwsAlg -> Maybe KeyId -> Payload -> ByteString
sigTarget a kid payload = B.intercalate "." $ map B64.encode [encodeHeader hdr, bytes]
  where
    hdr = defJwsHdr {jwsAlg = a, jwsKid = kid, jwsCty = contentType}
    (contentType, bytes) = case payload of
        Claims c       -> (Nothing, c)
        Nested (Jwt b) -> (Just "JWT", b)

type JwsVerifier = JwsAlg -> ByteString -> ByteString -> Bool


decode :: JwsVerifier -> ByteString -> Either JwtError Jws
decode verify jwt = do
    decodableJwt <- P.parseJwt jwt
    case decodableJwt of
        P.DecodableJws hdr (P.Payload p) (P.Sig sig) (P.SigTarget signed) ->
          if verify (jwsAlg hdr) signed sig
              then Right (hdr, p)
              else Left BadSignature
        _ -> Left (BadHeader "JWT is not a JWS")
