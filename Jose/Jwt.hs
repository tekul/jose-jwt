{-# LANGUAGE OverloadedStrings, FlexibleContexts #-}
{-# OPTIONS_HADDOCK prune #-}

-- | High-level JWT encoding and decoding.
--
-- See the Jose.Jws and Jose.Jwe modules for specific JWS and JWE examples.
--
-- Example usage with a key stored as a JWK:
--
-- >>> import Jose.Jwe
-- >>> import Jose.Jwa
-- >>> import Jose.Jwk
-- >>> import Data.ByteString
-- >>> import Data.Aeson (decodeStrict)
-- >>> let jsonJwk = "{\"kty\":\"RSA\", \"kid\":\"mykey\", \"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\", \"e\":\"AQAB\", \"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"}" :: ByteString
-- >>> let Just jwk = decodeStrict jsonJwk :: Maybe Jwk
-- >>> Right (Jwt jwtEncoded) <- encode [jwk] (JwsEncoding RS256) (Claims "public claims")
-- >>> Right jwtDecoded <- Jose.Jwt.decode [jwk] (Just (JwsEncoding RS256)) jwtEncoded
-- >>> jwtDecoded
-- Jws (JwsHeader {jwsAlg = RS256, jwsTyp = Nothing, jwsCty = Nothing, jwsKid = Just (KeyId "mykey")},"public claims")

module Jose.Jwt
    ( module Jose.Types
    , encode
    , decode
    , decodeClaims
    )
where

import Control.Monad (msum, when, unless)
import Control.Monad.Trans (lift)
import Control.Monad.Trans.Except
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.PubKey.RSA (PrivateKey(..))
import Crypto.Random (MonadRandom)
import Data.Aeson (decodeStrict',FromJSON)
import Data.ByteString (ByteString)
import Data.Maybe (isNothing)
import qualified Data.ByteString.Char8 as BC

import qualified Jose.Internal.Base64 as B64
import qualified Jose.Internal.Parser as P
import Jose.Types
import Jose.Jwk
import Jose.Jwa

import qualified Jose.Jws as Jws
import qualified Jose.Jwe as Jwe


-- | Use the supplied JWKs to create a JWT.
-- The list of keys will be searched to locate one which is
-- consistent with the chosen encoding algorithms.
--
encode :: MonadRandom m
    => [Jwk]                     -- ^ The key or keys. At least one must be consistent with the chosen algorithm
    -> JwtEncoding               -- ^ The encoding algorithm(s) used to encode the payload
    -> Payload                   -- ^ The payload (claims)
    -> m (Either JwtError Jwt)   -- ^ The encoded JWT, if successful
encode jwks encoding msg = runExceptT $ case encoding of
    JwsEncoding None -> case msg of
        Claims p -> return $ Jwt $ BC.intercalate "." [unsecuredHdr, B64.encode p]
        Nested _ -> throwE BadClaims
    JwsEncoding a    -> case filter (canEncodeJws a) jwks of
        []    -> throwE (KeyError "No matching key found for JWS algorithm")
        (k:_) -> ExceptT . return =<< lift (Jws.jwkEncode a k msg)
    JweEncoding a e -> case filter (canEncodeJwe a) jwks of
        []    -> throwE (KeyError "No matching key found for JWE algorithm")
        (k:_) -> ExceptT . return =<< lift (Jwe.jwkEncode a e k msg)
  where
    unsecuredHdr = B64.encode (BC.pack "{\"alg\":\"none\"}")


-- | Uses the supplied keys to decode a JWT.
-- Locates a matching key by header @kid@ value where possible
-- or by suitable key type for the encoding algorithm.
--
-- The algorithm(s) used can optionally be supplied for validation
-- by setting the @JwtEncoding@ parameter, in which case an error will
-- be returned if they don't match. If you expect the tokens to use
-- a particular algorithm, then you should set this parameter.
--
-- For unsecured tokens (with algorithm "none"), the expected algorithm
-- must be set to @Just (JwsEncoding None)@ or an error will be returned.
decode :: MonadRandom m
    => [Jwk]                           -- ^ The keys to use for decoding
    -> Maybe JwtEncoding               -- ^ The expected encoding information
    -> ByteString                      -- ^ The encoded JWT
    -> m (Either JwtError JwtContent)  -- ^ The decoded JWT payload, if successful
decode keySet encoding jwt = runExceptT $ do
    decodableJwt <- ExceptT (return (P.parseJwt jwt))

    decodings <- case (decodableJwt, encoding) of
        (P.Unsecured p, Just (JwsEncoding None)) -> return [Just (Unsecured p)]
        (P.Unsecured _, _) -> throwE (BadAlgorithm "JWT is unsecured but expected 'alg' was not 'none'")
        (P.DecodableJws hdr _ _ _, e) -> do
            unless (isNothing e || e == Just (JwsEncoding (jwsAlg hdr))) $
                throwE (BadAlgorithm "Expected 'alg' doesn't match JWS header")
            ks <- checkKeys $ filter (canDecodeJws hdr) keySet
            mapM decodeWithJws ks
        (P.DecodableJwe hdr _ _ _ _ _, e) -> do
            unless (isNothing e || e == Just (JweEncoding (jweAlg hdr) (jweEnc hdr))) $
                throwE (BadAlgorithm "Expected encoding doesn't match JWE header")
            ks <- checkKeys $ filter (canDecodeJwe hdr) keySet
            mapM decodeWithJwe ks
    case msum decodings of
        Nothing  -> throwE $ KeyError "None of the keys was able to decode the JWT"
        Just jwtContent -> return jwtContent
  where
    decodeWithJws :: MonadRandom m => Jwk -> ExceptT JwtError m (Maybe JwtContent)
    decodeWithJws k = either (const $ return Nothing) (return . Just . Jws) $ case k of
        Ed25519PublicJwk kPub _ -> Jws.ed25519Decode kPub jwt
        Ed25519PrivateJwk _ kPub _ -> Jws.ed25519Decode kPub jwt
        RsaPublicJwk  kPub _ _ _ -> Jws.rsaDecode kPub jwt
        RsaPrivateJwk kPr  _ _ _ -> Jws.rsaDecode (private_pub kPr) jwt
        EcPublicJwk   kPub _ _ _ _ -> Jws.ecDecode kPub jwt
        EcPrivateJwk  kPr  _ _ _ _ -> Jws.ecDecode (ECDSA.toPublicKey kPr) jwt
        SymmetricJwk  kb   _ _ _ -> Jws.hmacDecode kb jwt

    decodeWithJwe :: MonadRandom m => Jwk -> ExceptT JwtError m (Maybe JwtContent)
    decodeWithJwe k = fmap (either (const Nothing) Just) (lift (Jwe.jwkDecode k jwt))

    checkKeys [] = throwE $ KeyError "No suitable key was found to decode the JWT"
    checkKeys ks = return ks


-- | Convenience function to return the claims contained in a JWS.
-- This is needed in situations such as client assertion authentication,
-- <https://tools.ietf.org/html/rfc7523>, where the contents of the JWT,
-- such as the @sub@ claim, may be required in order to work out
-- which key should be used to verify the token.
--
-- Obviously this should not be used by itself to decode a token since
-- no integrity checking is done and the contents may be forged.
decodeClaims :: (FromJSON a)
    => ByteString
    -> Either JwtError (JwtHeader, a)
decodeClaims jwt = do
    let components = BC.split '.' jwt
    when (length components /= 3) $ Left $ BadDots 2
    hdr    <- B64.decode (head components) >>= parseHeader
    claims <- B64.decode ((head . tail) components) >>= parseClaims
    return (hdr, claims)
  where
    parseClaims bs = maybe (Left BadClaims) Right $ decodeStrict' bs
