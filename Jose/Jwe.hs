{-# LANGUAGE OverloadedStrings #-}

module Jose.Jwe where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Crypto.Cipher.Types (AuthTag(..))
import Crypto.PubKey.RSA (PrivateKey, PublicKey)
import Crypto.Random.API (CPRG)
import Jose.Types
import qualified Jose.Internal.Base64 as B64
import Jose.Internal.Crypto
import Jose.Jwa


rsaEncode :: CPRG g => g -> Alg -> Enc -> PublicKey -> ByteString -> (ByteString, g)
rsaEncode rng a e pubKey claims = (jwe, rng'')
  where
    hdr = encodeHeader defHdr {jwtAlg = a, jwtEnc = Just e}
    (cmk, iv, rng') = generateCmkAndIV rng e
    (jweKey, rng'') = rsaEncrypt rng' a pubKey cmk
    aad = B64.encode hdr
    (ct, AuthTag sig) = encryptPayload e cmk iv aad claims
    jwe = B.intercalate "." $ map B64.encode [hdr, jweKey, iv, ct, sig]

rsaDecode :: PrivateKey -> ByteString -> Either JwtError Jwt
rsaDecode rsaKey jwt = do
    checkDots
    let components = BC.split '.' jwt
    let aad = head components
    [h, ek, iv, payload, sig] <- mapM B64.decode components
    hdr <- parseHeader h
    cek <- decryptContentKey (jwtAlg hdr) rsaKey ek
    encryption <- maybe (Left BadHeader) Right $ jwtEnc hdr
    claims <- decryptPayload encryption cek iv aad sig payload
    return (hdr, claims)
  where
    checkDots = case BC.count '.' jwt of
                    4 -> Right ()
                    _ -> Left $ BadDots 4

