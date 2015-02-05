{-# LANGUAGE OverloadedStrings, FlexibleContexts #-}
{-# OPTIONS_HADDOCK prune #-}

-- | High-level JWT encoding and decoding.
--
-- Example usage:
--
-- >>> import Jose.Jwe
-- >>> import Jose.Jwa
-- >>> import Jose.Jwk
-- >>> import Data.Aeson (decodeStrict)
-- >>> import Crypto.Random.AESCtr
-- >>> g <- makeSystem
-- >>> let jsonJwk = "{\"kty\":\"RSA\", \"kid\":\"mykey\", \"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\", \"e\":\"AQAB\", \"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"}"
-- >>> let Just jwk = decodeStrict jsonJwk :: Maybe Jwk
-- >>> let (Right jwtEncoded, g')  = encode g jwk (Signed RS256) Nothing "public claims"
-- >>> let (Right jwtDecoded, g'') = Jose.Jwt.decode g' [jwk] jwtEncoded
-- >>> jwtDecoded
-- Jws (JwsHeader {jwsAlg = RS256, jwsTyp = Nothing, jwsCty = Nothing, jwsKid = Just "mykey"},"public claims")

module Jose.Jwt
    ( module Jose.Types
    , encode
    , decode
    , decodeClaims
    )
where

import Control.Error
import Control.Monad.State.Strict
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.PubKey.RSA (PrivateKey(..))
import Crypto.Random (CPRG)
import Data.Aeson (decodeStrict')
import Data.ByteString (ByteString)
import Data.List (find)
import Data.Maybe (fromJust)
import qualified Data.ByteString.Char8 as BC

import qualified Jose.Internal.Base64 as B64
import Jose.Types
import Jose.Jwk
import Jose.Jwa

import qualified Jose.Jws as Jws
import qualified Jose.Jwe as Jwe


-- | Use the supplied JWKs to create a JWT.
-- The list of keys will be searched to locate one which is
-- consistent with the chosen algorithm.
--
encode :: (CPRG g)
       => g                               -- ^ Random number generator.
       -> [Jwk]                           -- ^ The key or keys. At least one must be consistent with the chosen algorithm
       -> Alg                             -- ^ The JWS or JWE algorithm
       -> Maybe Enc                       -- ^ The payload encryption algorithm (if applicable)
       -> ByteString                      -- ^ The payload (claims)
       -> (Either JwtError ByteString, g) -- ^ The encoded JWT, if successful
encode rng jwks alg enc msg = flip runState rng $ runEitherT $ case alg of
    Signed a    -> do
        unless (isNothing enc) $ left (BadAlgorithm "Enc cannot be set for a JWS")
        case findMatchingJwsKeys jwks (defJwsHdr { jwsAlg = a }) of
            []     -> left (KeyError "No matching key found for JWS algorithm")
            (k:_) -> hoistEither =<< state (\g -> Jws.jwkEncode g a k msg)
    Encrypted a -> do
        e <- hoistEither $ note (BadAlgorithm "Enc must be supplied for a JWE") enc
        case findMatchingJweKeys jwks (defJweHdr { jweAlg = a, jweEnc = e }) of
            []     -> left (KeyError "No matching key found for JWE algorithm")
            (k:_) -> hoistEither =<< state (\g -> Jwe.jwkEncode g a e k msg)


-- | Uses the supplied keys to decode a JWT.
-- Locates a matching key by header @kid@ value where possible
-- or by suitable key type.
-- The JWK @use@ and @alg@ options are currently ignored.
decode :: CPRG g
       => g                        -- ^ Random number generator. Only used for RSA blinding
       -> [Jwk]                    -- ^ The keys to use for decoding
       -> ByteString               -- ^ The encoded JWT
       -> (Either JwtError Jwt, g) -- ^ The decoded JWT, if successful
decode rng keySet jwt = flip runState rng $ runEitherT $ do
    let components = BC.split '.' jwt
    when (length components < 3) $ left $ BadDots 2
    hdr <- B64.decode (head components) >>= hoistEither . parseHeader
    ks  <- findKeys hdr keySet
    -- Now we have one or more suitable keys.
    -- Try each in turn until successful
    let decodeWith = case hdr of
                       JwsH _ -> decodeWithJws
                       _      -> decodeWithJwe
    decodings <- mapM decodeWith ks
    maybe (left $ KeyError "None of the keys was able to decode the JWT") (return . fromJust) $ find isJust decodings
  where
    decodeWithJws :: CPRG g => Jwk -> EitherT JwtError (State g) (Maybe Jwt)
    decodeWithJws k = either (const $ return Nothing) (return . Just . Jws) $ case k of
        RsaPublicJwk  kPub _ _ _ -> Jws.rsaDecode kPub jwt
        RsaPrivateJwk kPr  _ _ _ -> Jws.rsaDecode (private_pub kPr) jwt
        EcPublicJwk   kPub _ _ _ -> Jws.ecDecode kPub jwt
        EcPrivateJwk  kPr  _ _ _ -> Jws.ecDecode (ECDSA.toPublicKey kPr) jwt
        SymmetricJwk  kb   _ _ _ -> Jws.hmacDecode kb jwt

    decodeWithJwe :: CPRG g => Jwk -> EitherT JwtError (State g) (Maybe Jwt)
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


findKeys :: Monad m => JwtHeader -> [Jwk] -> EitherT JwtError m [Jwk]
findKeys hdr jwks = checkKeys $ case hdr of
    JweH h -> findMatchingJweKeys jwks h
    JwsH h -> findMatchingJwsKeys jwks h
  where
    -- TODO Move checks to JWK and support better error messages
    checkKeys [] = left $ KeyError "No suitable key was found to decode the JWT"
    checkKeys ks = return ks

