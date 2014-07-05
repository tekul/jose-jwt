{-# LANGUAGE OverloadedStrings #-}

-- | JWS HMAC and RSA signed token support.
--
-- Example usage with HMAC:
--
-- >>> import Jose.Jws
-- >>> import Jose.Jwa
-- >>> let jwt = hmacEncode HS256 "secretmackey" "secret claims"
-- >>> jwt
-- "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0IGNsYWltcw.Hk9VZbfMHEC_IGVHnAi25HgWR91XMneqYCl7F5izQkM"
-- >>> hmacDecode "wrongkey" jwt
-- Left BadSignature
-- >>> hmacDecode "secretmackey" jwt
-- Right (JwtHeader {jwtAlg = Signed HS256, jwtEnc = Nothing, jwtTyp = Nothing, jwtCty = Nothing, jwtZip = Nothing, jwtKid = Nothing},"secret claims")

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

-- | Create a JWS with an HMAC for validation.
hmacEncode :: JwsAlg       -- ^ The MAC algorithm to use
           -> ByteString   -- ^ The MAC key
           -> ByteString   -- ^ The JWT claims (token content)
           -> ByteString   -- ^ The encoded JWS token
hmacEncode a key = encode (hmacSign a key) $ defHdr {jwtAlg = Signed a}

-- | Decodes and validates an HMAC signed JWS.
hmacDecode :: ByteString          -- ^ The HMAC key
           -> ByteString          -- ^ The JWS token to decode
           -> Either JwtError Jwt -- ^ The decoded token if successful
hmacDecode key = decode (\alg -> hmacVerify alg key)

-- | Creates a JWS with an RSA signature.
rsaEncode :: JwsAlg       -- ^ The RSA algorithm to use
          -> PrivateKey   -- ^ The key to sign with
          -> ByteString   -- ^ The JWT claims (token content)
          -> ByteString   -- ^ The encoded JWS token
rsaEncode a k = encode (rsaSign a k) $ defHdr {jwtAlg = Signed a}

-- | Decode and validate an RSA signed JWS.
rsaDecode :: PublicKey            -- ^ The key to check the signature with
          -> ByteString           -- ^ The encoded JWS
          -> Either JwtError Jwt  -- ^ The decoded token if successful
rsaDecode key = decode (\alg -> rsaVerify alg key)

encode :: (ByteString -> ByteString) -> JwtHeader -> ByteString -> ByteString
encode sign hdr payload = B.intercalate "." [hdrPayload, B64.encode $ sign hdrPayload]
  where
    hdrPayload = B.intercalate "." $ map B64.encode [encodeHeader hdr, payload]

type JwsVerifier = JwsAlg -> ByteString -> ByteString -> Bool

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

