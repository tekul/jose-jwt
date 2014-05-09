{-# LANGUAGE OverloadedStrings #-}

module Data.Jwt
    ( module Data.Jwt.Types
    , module Data.Jwt.Internal
    , jwsHmacDecode
    , jwsHmacEncode
    , jwsRsaDecode
    , jwsRsaEncode
    , jweRsaDecode
    , jweRsaEncode
    -- TODO: These are exported for tests at the moment
    , jwsEncode
    , jwsDecode
    , defHdr
    , rsaEncrypt
    , generateCmkAndIV
    , encodeHeader
    ) where

import Control.Monad.State.Strict
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.ByteString.Lazy (fromChunks, toChunks)
import qualified Data.ByteString.Char8 as BC
import qualified Data.Aeson as Aeson (encode, decode)
import Crypto.Cipher.Types (AuthTag(..))
import Crypto.PubKey.RSA (PrivateKey, PublicKey)
import Crypto.Random.API (CPRG)
import Data.Jwt.Types
import Data.Jwt.Internal
import Data.Jwt.Crypto

{-| Returns the JWT header, allowing the details to be inspected
 - before decoding. Useful when you need to support multiple
 - encoding strategies and don't know in advance how a
 - particular JWT will be encoded.
 -}

header :: ByteString -> Either JwtError JwtHeader
header = undefined

defHdr = JwtHeader None Nothing Nothing Nothing

jwsHmacEncode :: Alg -> ByteString -> ByteString -> ByteString
jwsHmacEncode a key = jwsEncode (hmacSign a key) hdr
  where
    hdr = encodeHeader defHdr {alg = a}

jwsHmacDecode :: ByteString -> ByteString -> Either JwtError Jwt
jwsHmacDecode key = jwsDecode (\hdr -> hmacVerify (alg hdr) key)

jwsRsaEncode :: Alg -> PrivateKey -> ByteString -> ByteString
jwsRsaEncode a k = jwsEncode (rsaSign a k) $ encodeHeader defHdr {alg = a}

jwsRsaDecode :: PublicKey -> ByteString -> Either JwtError Jwt
jwsRsaDecode key = jwsDecode (\hdr -> rsaVerify (alg hdr) key)

 -- | Encode a JWT from a JSON Header, signing algorithm and payload
 -- Uses a ByteString for the header to make testing agains the specs
 -- easier.
jwsEncode :: (ByteString -> ByteString) -> ByteString -> ByteString -> ByteString
jwsEncode sign hdr payload = B.intercalate "." [hdrPayload, b64Encode $ sign hdrPayload]
  where
    hdrPayload = B.intercalate "." $ map b64Encode [hdr, payload]

type JwsVerifier = JwtHeader -> ByteString -> ByteString -> Bool

-- Decodes and parses the JWT header and returns the header and the
-- byte segments of the JWT.
jwsDecode :: JwsVerifier -> ByteString -> Either JwtError Jwt
jwsDecode verify jwt = do
    checkDots 2 jwt
    let (hdrPayload, sig) = spanEndDot jwt
    sigBytes <- b64Decode sig
    [h, payload] <- mapM b64Decode $ BC.split '.' hdrPayload
    hdr <- parseHeader h
    if verify hdr hdrPayload sigBytes
      then Right (hdr, payload)
      else Left BadSignature

jweRsaEncode :: CPRG g => g -> Alg -> Enc -> PublicKey -> ByteString -> (ByteString, g)
jweRsaEncode rng a e pubKey claims = (b64DotIntercalate [hdr, jweKey, iv, ct, sig], rng'')
  where
    hdr = encodeHeader defHdr {alg = a, enc = Just e}
    (cmk, iv, rng') = generateCmkAndIV rng e
    (jweKey, rng'') = rsaEncrypt rng' a pubKey cmk
    aad = b64Encode hdr
    (ct, AuthTag sig) = encryptPayload e cmk iv aad claims

jweRsaDecode :: PrivateKey -> ByteString -> Either JwtError Jwt
jweRsaDecode rsaKey jwt = do
    checkDots 4 jwt
    let components = BC.split '.' jwt
    let aad = head components
    [h, ek, iv, payload, sig] <- mapM b64Decode components
    hdr <- parseHeader h
    cek <- decryptContentKey (alg hdr) rsaKey ek
    encryption <- maybe (Left BadHeader) Right $ enc hdr
    claims <- decryptPayload encryption cek iv aad sig payload
    return (hdr, claims)

encodeHeader :: JwtHeader -> ByteString
encodeHeader = B.concat . toChunks . Aeson.encode

parseHeader :: ByteString -> Either JwtError JwtHeader
parseHeader hdr = case Aeson.decode $ fromChunks [hdr] of
    Just h -> Right h
    Nothing -> Left BadHeader

checkDots n jwt
    | count == n = Right ()
    | otherwise  = Left $ BadDots count
  where count = BC.count '.' jwt

spanEndDot bs = let (toDot, end) = BC.spanEnd (/= '.') bs
                in  (B.init toDot, end)

b64DotIntercalate :: [ByteString] -> ByteString
b64DotIntercalate bs = B.intercalate "." $ map b64Encode bs
