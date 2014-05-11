{-# LANGUAGE OverloadedStrings #-}

module Jose.Jws where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Crypto.PubKey.RSA (PrivateKey, PublicKey)
import Jose.Types
import qualified Jose.Internal.Base64 as B64
import Jose.Internal.Crypto
import Jose.Jwa


hmacEncode :: Alg -> ByteString -> ByteString -> ByteString
hmacEncode a key = encode (hmacSign a key) hdr
  where
    hdr = encodeHeader defHdr {alg = a}

hmacDecode :: ByteString -> ByteString -> Either JwtError Jwt
hmacDecode key = decode (\hdr -> hmacVerify (alg hdr) key)

rsaEncode :: Alg -> PrivateKey -> ByteString -> ByteString
rsaEncode a k = encode (rsaSign a k) $ encodeHeader defHdr {alg = a}

rsaDecode :: PublicKey -> ByteString -> Either JwtError Jwt
rsaDecode key = decode (\hdr -> rsaVerify (alg hdr) key)

 -- | Encode a JWT from a JSON Header, signing algorithm and payload
 -- Uses a ByteString for the header to make testing agains the specs
 -- easier.
encode :: (ByteString -> ByteString) -> ByteString -> ByteString -> ByteString
encode sign hdr payload = B.intercalate "." [hdrPayload, B64.encode $ sign hdrPayload]
  where
    hdrPayload = B.intercalate "." $ map B64.encode [hdr, payload]

type JwsVerifier = JwtHeader -> ByteString -> ByteString -> Bool

-- Decodes and parses the JWT header and returns the header and the
-- byte segments of the JWT.
decode :: JwsVerifier -> ByteString -> Either JwtError Jwt
decode verify jwt = do
    checkDots
    let (hdrPayload, sig) = spanEndDot jwt
    sigBytes <- B64.decode sig
    [h, payload] <- mapM B64.decode $ BC.split '.' hdrPayload
    hdr <- parseHeader h
    if verify hdr hdrPayload sigBytes
      then Right (hdr, payload)
      else Left BadSignature
  where
    checkDots = case (BC.count '.' jwt) of
                    2 -> Right ()
                    _ -> Left $ BadDots 2
    spanEndDot bs = let (toDot, end) = BC.spanEnd (/= '.') bs
                    in  (B.init toDot, end)

