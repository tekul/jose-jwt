{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_HADDOCK prune #-}

module Jose.Jwt
    ( module Jose.Types
    , decode
    )
where

import Crypto.PubKey.RSA (PrivateKey(..))
import Data.ByteString (ByteString)
import Data.List (find)
import qualified Data.ByteString.Char8 as BC

import qualified Jose.Internal.Base64 as B64
import Jose.Types
import Jose.Jwk

import qualified Jose.Jws as Jws
import qualified Jose.Jwe as Jwe


-- | Uses the supplied keys to decode a JWT.
-- Locates a matching key by header @kid@ value where possible
-- or by suitable key type.
-- The JWK @use@ and @alg@ options are currently ignored.
decode :: JwkSet               -- ^ The keys to use for decoding
       -> ByteString           -- ^ The encoded JWT
       -> Either JwtError Jwt  -- ^ The decoded JWT, if successful
decode keySet jwt = do
    let components = BC.split '.' jwt
    hdr <- (B64.decode $ head components) >>= parseHeader
    ks <- findKeys hdr (keys keySet)
    -- Now we have one or more suitable keys.
    -- Try each in turn until successful
    let decodeWith = case hdr of
                       JwsH _ -> decodeWithJws
                       _      -> decodeWithJwe
    let decodings = map decodeWith ks
    maybe (Left $ KeyError "None of the keys was able to decode the JWT") id $ find (isRight) decodings
  where
    decodeWithJws :: Jwk -> Either JwtError Jwt
    decodeWithJws k = fmap Jws $ case k of
        RsaPublicJwk  kPub _ _ _ -> Jws.rsaDecode kPub jwt
        RsaPrivateJwk kPr  _ _ _ -> Jws.rsaDecode (private_pub kPr) jwt
        SymmetricJwk  kb   _ _ _ -> Jws.hmacDecode kb jwt

    decodeWithJwe :: Jwk -> Either JwtError Jwt
    decodeWithJwe k = fmap Jwe $ case k of
        RsaPrivateJwk kPr _ _ _ -> Jwe.rsaDecode kPr jwt
        _                       -> Left $ KeyError "Not a JWE key (shoudln't happen)"
    isRight (Left _)  = False
    isRight (Right _) = True

findKeys :: JwtHeader -> [Jwk] -> Either JwtError [Jwk]
findKeys hdr jwks = checkKeys $ case hdr of
    JweH h -> findMatchingJweKeys jwks h
    JwsH h -> findMatchingJwsKeys jwks h
  where
    -- TODO Move checks to JWK and support better error messages
    checkKeys [] = Left $ KeyError "No suitable key was found to decode the JWT"
    checkKeys ks = return ks
