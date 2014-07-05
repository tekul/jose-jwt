{-# LANGUAGE OverloadedStrings #-}

module Jose.Jws
    ( hmacEncode
    , hmacDecode
    , rsaEncode
    , rsaDecode
    )
where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Crypto.PubKey.RSA (PrivateKey, PublicKey)
import Jose.Types
import qualified Jose.Internal.Base64 as B64
import Jose.Internal.Crypto
import Jose.Jwa


hmacEncode :: JwsAlg -> ByteString -> ByteString -> ByteString
hmacEncode a key = encode (hmacSign a key) $ defHdr {jwtAlg = Signed a}

hmacDecode :: ByteString -> ByteString -> Either JwtError Jwt
hmacDecode key = decode (\alg -> hmacVerify alg key)

rsaEncode :: JwsAlg -> PrivateKey -> ByteString -> ByteString
rsaEncode a k = encode (rsaSign a k) $ defHdr {jwtAlg = Signed a}

rsaDecode :: PublicKey -> ByteString -> Either JwtError Jwt
rsaDecode key = decode (\alg -> rsaVerify alg key)

encode :: (ByteString -> ByteString) -> JwtHeader -> ByteString -> ByteString
encode sign hdr payload = B.intercalate "." [hdrPayload, B64.encode $ sign hdrPayload]
  where
    hdrPayload = B.intercalate "." $ map B64.encode [encodeHeader hdr, payload]

type JwsVerifier = JwsAlg -> ByteString -> ByteString -> Bool

-- Decodes and parses the JWT header and returns the header and the
-- byte segments of the JWT.
decode :: JwsVerifier -> ByteString -> Either JwtError Jwt
decode verify jwt = do
    checkDots
    let (hdrPayload, sig) = spanEndDot jwt
    sigBytes <- B64.decode sig
    [h, payload] <- mapM B64.decode $ BC.split '.' hdrPayload
    hdr <- parseHeader h
    alg <- case jwtAlg hdr of
        Signed a -> Right a
        _        -> Left BadHeader
    if verify alg hdrPayload sigBytes
      then Right (hdr, payload)
      else Left BadSignature
  where
    checkDots = case (BC.count '.' jwt) of
                    2 -> Right ()
                    _ -> Left $ BadDots 2
    spanEndDot bs = let (toDot, end) = BC.spanEnd (/= '.') bs
                    in  (B.init toDot, end)

