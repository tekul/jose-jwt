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

-- | Creates a JWE.
rsaEncode :: CPRG g
          => g               -- ^ Random number generator
          -> JweAlg          -- ^ RSA algorithm to use (@RSA_OAEP@ or @RSA1_5@)
          -> Enc             -- ^ Content encryption algorithm
          -> PublicKey       -- ^ RSA key to encrypt with
          -> ByteString      -- ^ The JWT claims (content)
          -> (ByteString, g) -- ^ The encoded JWE and new generator
rsaEncode rng a e pubKey claims = (jwe, rng'')
  where
    hdr = encodeHeader defHdr {jwtAlg = Encrypted a, jwtEnc = Just e}
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
    alg <- case jwtAlg hdr of
               Encrypted a -> Right a
               _           -> Left BadHeader
    cek <- rsaDecrypt alg rsaKey ek
    encryption <- maybe (Left BadHeader) Right $ jwtEnc hdr
    claims <- decryptPayload encryption cek iv aad sig payload
    return (hdr, claims)
  where
    checkDots = case BC.count '.' jwt of
                    4 -> Right ()
                    _ -> Left $ BadDots 4

