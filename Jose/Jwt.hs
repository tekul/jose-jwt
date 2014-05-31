{-# LANGUAGE OverloadedStrings #-}

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
import Jose.Jwa (Alg, Enc)

import qualified Jose.Jws as Jws
import qualified Jose.Jwe as Jwe


-- Uses the supplied keys to decode a jwt,
-- matching keys by header kid value where possible
-- or by suitable key type.
-- The JWK "use" and "alg" options are currently ignored.
decode :: JwkSet -> ByteString -> Either JwtError Jwt
decode keySet jwt = do
    let components = BC.split '.' jwt
    hdr <- (B64.decode $ head components) >>= parseHeader
    ks  <- findKeys (jwtKid hdr) (jwtAlg hdr) (jwtEnc hdr) (keys keySet)
    -- Now we have one or more suitable keys.
    -- Try each in turn until successful
    let isJws = (jwtEnc hdr == Nothing)
    let decodings = map (decodeWith isJws) ks
    maybe (Left $ KeyError "None of the keys was able to decode the JWT") id $ find (isRight) decodings
  where
    decodeWith :: Bool -> Jwk -> Either JwtError Jwt
    decodeWith isJws k = case k of
        RsaPublicJwk  kPub _ _ _ -> Jws.rsaDecode kPub jwt
        RsaPrivateJwk kPr  _ _ _ -> if isJws
                                       then Jws.rsaDecode (private_pub kPr) jwt
                                       else Jwe.rsaDecode kPr jwt
        SymmetricJwk  kb   _ _ _ -> Jws.hmacDecode kb jwt
    isRight (Left _)  = False
    isRight (Right _) = True

findKeys :: Maybe KeyId -> Alg -> Maybe Enc -> [Jwk] -> Either JwtError [Jwk]
findKeys kid alg enc jwks = case keyById of
    Nothing -> case filter (canDecode alg enc) jwks of
        [] -> Left $ KeyError "No suitable key was found to decode the JWT"
        ks -> return ks
    Just k  -> if canDecode alg enc k
                  then return [k]
                  else Left $ KeyError "Matching 'kid' key cannot decode the JWT"
  where
    keyById = maybe Nothing (findKeyById jwks) kid
