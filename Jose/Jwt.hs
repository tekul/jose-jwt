{-# LANGUAGE OverloadedStrings, FlexibleContexts #-}
{-# OPTIONS_HADDOCK prune #-}

-- | High-level JWT encoding and decoding.
--
-- Example usage:
--
-- >>> import Jose.Jwe
-- >>> import Jose.Jwa
-- >>> import Jose.Jwk
-- >>> import Data.ByteString
-- >>> import Data.Aeson (decodeStrict)
-- >>> import Crypto.Random.AESCtr
-- >>> g <- makeSystem
-- >>> let jsonJwk = "{\"kty\":\"RSA\", \"kid\":\"mykey\", \"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\", \"e\":\"AQAB\", \"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"}" :: ByteString
-- >>> let Just jwk = decodeStrict jsonJwk :: Maybe Jwk
-- >>> let (Right (Jwt jwtEncoded), g')  = encode g [jwk] (JwsEncoding RS256) (Claims "public claims")
-- >>> let (Right jwtDecoded, g'') = Jose.Jwt.decode g' [jwk] (Just (JwsEncoding RS256)) jwtEncoded
-- >>> jwtDecoded
-- Jws (JwsHeader {jwsAlg = RS256, jwsTyp = Nothing, jwsCty = Nothing, jwsKid = Just (KeyId "mykey")},"public claims")

module Jose.Jwt
    ( module Jose.Types
    , encode
    , decode
    , decodeClaims
    )
where

import Control.Monad.State.Strict
import Control.Monad.Trans.Either
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.PubKey.RSA (PrivateKey(..))
import Crypto.Random (CPRG)
import Data.Aeson (decodeStrict')
import Data.ByteString (ByteString)
import Data.List (find)
import Data.Maybe (fromJust, isJust, isNothing)
import qualified Data.ByteString.Char8 as BC

import qualified Jose.Internal.Base64 as B64
import Jose.Types
import Jose.Jwk
import Jose.Jwa

import qualified Jose.Jws as Jws
import qualified Jose.Jwe as Jwe


-- | Use the supplied JWKs to create a JWT.
-- The list of keys will be searched to locate one which is
-- consistent with the chosen encoding algorithms.
--
encode :: (CPRG g)
       => g                          -- ^ Random number generator
       -> [Jwk]                      -- ^ The key or keys. At least one must be consistent with the chosen algorithm
       -> JwtEncoding                -- ^ The encoding algorithm(s) used to encode the payload
       -> Payload                    -- ^ The payload (claims)
       -> (Either JwtError Jwt, g)   -- ^ The encoded JWT, if successful
encode rng jwks encoding msg = flip runState rng $ runEitherT $ case encoding of
    JwsEncoding None -> case msg of
        Claims p -> return $ Jwt $ BC.intercalate "." [unsecuredHdr, B64.encode p]
        Nested _ -> left BadClaims
    JwsEncoding a    -> case filter (canEncodeJws a) jwks of
        []    -> left (KeyError "No matching key found for JWS algorithm")
        (k:_) -> hoistEither =<< state (\g -> Jws.jwkEncode g a k msg)
    JweEncoding a e -> case filter (canEncodeJwe a) jwks of
        []    -> left (KeyError "No matching key found for JWE algorithm")
        (k:_) -> hoistEither =<< state (\g -> Jwe.jwkEncode g a e k msg)
  where
    unsecuredHdr = B64.encode "{\"alg\":\"none\"}"


-- | Uses the supplied keys to decode a JWT.
-- Locates a matching key by header @kid@ value where possible
-- or by suitable key type for the encoding algorithm.
--
-- The algorithm(s) used can be optionally be supplied for validation
-- by setting the @JwtEncoding@ parameter, in which case an error will
-- be returned if they don't match.
--
-- For unsecured tokens (with algorithm "none"), the expected algorithm
-- must be set to @Just (JwsEncoding None)@ or an error will be returned.
decode :: CPRG g
       => g                               -- ^ Random number generator. Only used for RSA blinding
       -> [Jwk]                           -- ^ The keys to use for decoding
       -> Maybe JwtEncoding               -- ^ The expected encoding information
       -> ByteString                      -- ^ The encoded JWT
       -> (Either JwtError JwtContent, g) -- ^ The decoded JWT payload, if successful
decode rng keySet encoding jwt = flip runState rng $ runEitherT $ do
    let components = BC.split '.' jwt
    when (length components < 3) $ left $ BadDots 2
    hdr <- B64.decode (head components) >>= hoistEither . parseHeader
    ks  <- findDecodingKeys hdr keySet
    -- Now we have one or more suitable keys (or none for the unsecured case).
    -- Try each in turn until successful
    decodings <- case hdr of
        UnsecuredH -> do
            unless (encoding == Just (JwsEncoding None)) $ left (BadAlgorithm "JWT is unsecured but expected 'alg' was not 'none'")
            B64.decode (components !! 1) >>= \p -> return [Just (Unsecured p)]
        JwsH h     -> do
            unless (isNothing encoding || encoding == Just (JwsEncoding (jwsAlg h))) $ left (BadAlgorithm "Expected 'alg' doesn't match JWS header")
            mapM decodeWithJws ks
        JweH h     -> do
            unless (isNothing encoding || encoding == Just (JweEncoding (jweAlg h) (jweEnc h))) $ left (BadAlgorithm "Expected encoding doesn't match JWE header")
            mapM decodeWithJwe ks
    maybe (left $ KeyError "None of the keys was able to decode the JWT") (return . fromJust) $ find isJust decodings
  where
    decodeWithJws :: CPRG g => Jwk -> EitherT JwtError (State g) (Maybe JwtContent)
    decodeWithJws k = either (const $ return Nothing) (return . Just . Jws) $ case k of
        RsaPublicJwk  kPub _ _ _ -> Jws.rsaDecode kPub jwt
        RsaPrivateJwk kPr  _ _ _ -> Jws.rsaDecode (private_pub kPr) jwt
        EcPublicJwk   kPub _ _ _ _ -> Jws.ecDecode kPub jwt
        EcPrivateJwk  kPr  _ _ _ _ -> Jws.ecDecode (ECDSA.toPublicKey kPr) jwt
        SymmetricJwk  kb   _ _ _ -> Jws.hmacDecode kb jwt

    decodeWithJwe :: CPRG g => Jwk -> EitherT JwtError (State g) (Maybe JwtContent)
    decodeWithJwe k = case k of
        RsaPrivateJwk kPr _ _ _ -> do
            e <- state (\g -> Jwe.rsaDecode g kPr jwt)
            either (const $ return Nothing) (return . Just . Jwe) e
        _                       -> left $ KeyError "Not a JWE key (shouldn't happen)"

-- | Convenience function to return the claims contained in a JWT.
-- This is required in situations such as client assertion authentication,
-- where the contents of the JWT may be required in order to work out
-- which key should be used to verify the token.
-- Obviously this should not be used by itself to decode a token since
-- no integrity checking is done and the contents may be forged.
decodeClaims :: ByteString
             -> Either JwtError (JwtHeader, JwtClaims)
decodeClaims jwt = do
    let components = BC.split '.' jwt
    when (length components /= 3) $ Left $ BadDots 2
    hdr    <- B64.decode (head components) >>= parseHeader
    claims <- B64.decode ((head . tail) components) >>= parseClaims
    return (hdr, claims)
  where
    parseClaims bs = maybe (Left BadClaims) Right $ decodeStrict' bs


findDecodingKeys :: Monad m => JwtHeader -> [Jwk] -> EitherT JwtError m [Jwk]
findDecodingKeys hdr jwks = case hdr of
    JweH h -> checkKeys $ filter (canDecodeJwe h) jwks
    JwsH h -> checkKeys $ filter (canDecodeJws h) jwks
    UnsecuredH -> return []
  where
    -- TODO Move checks to JWK and support better error messages
    checkKeys [] = left $ KeyError "No suitable key was found to decode the JWT"
    checkKeys ks = return ks
