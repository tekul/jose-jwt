{-# LANGUAGE OverloadedStrings #-}

-- | JWS HMAC and RSA signed token support.
--
-- Example usage with HMAC:
--
-- >>> import Jose.Jws
-- >>> import Jose.Jwa
-- >>> let Right jwt = hmacEncode HS256 "secretmackey" "public claims"
-- >>> jwt
-- "eyJhbGciOiJIUzI1NiJ9.cHVibGljIGNsYWltcw.GDV7RdBrCYfCtFCZZGPy_sWry4GwfX3ckMywXUyxBsc"
-- >>> hmacDecode "wrongkey" jwt
-- Left BadSignature
-- >>> hmacDecode "secretmackey" jwt
-- Right (JwsHeader {jwsAlg = HS256, jwsTyp = Nothing, jwsCty = Nothing, jwsKid = Nothing},"public claims")

module Jose.Jws
    ( hmacEncode
    , hmacDecode
    , rsaEncode
    , rsaDecode
    )
where

import Control.Applicative
import Control.Monad (unless)
import Crypto.PubKey.RSA (PrivateKey(..), PublicKey(..), generateBlinder)
import Crypto.Random (CPRG)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Jose.Types
import qualified Jose.Internal.Base64 as B64
import Jose.Internal.Crypto
import Jose.Jwa

-- | Create a JWS with an HMAC for validation.
hmacEncode :: JwsAlg       -- ^ The MAC algorithm to use
           -> ByteString   -- ^ The MAC key
           -> ByteString   -- ^ The public JWT claims (token content)
           -> Either JwtError ByteString   -- ^ The encoded JWS token
hmacEncode a key payload = let st = sigTarget a payload
                           in  (\mac -> B.concat [st, ".", B64.encode mac]) <$> hmacSign a key st

-- | Decodes and validates an HMAC signed JWS.
hmacDecode :: ByteString          -- ^ The HMAC key
           -> ByteString          -- ^ The JWS token to decode
           -> Either JwtError Jws -- ^ The decoded token if successful
hmacDecode key = decode (`hmacVerify` key)

-- | Creates a JWS with an RSA signature.
rsaEncode :: CPRG g
          => g
          -> JwsAlg                           -- ^ The RSA algorithm to use
          -> PrivateKey                       -- ^ The key to sign with
          -> ByteString                       -- ^ The public JWT claims (token content)
          -> (Either JwtError ByteString, g)  -- ^ The encoded JWS token
rsaEncode rng a pk payload = (sign blinder, rng')
  where
    (blinder, rng') = generateBlinder rng (public_n $ private_pub pk)

    st = sigTarget a payload

    sign b = case rsaSign (Just b) a pk st of
        Right sig -> Right $ B.concat [st, ".", B64.encode sig]
        err       -> err


-- | Decode and validate an RSA signed JWS.
rsaDecode :: PublicKey            -- ^ The key to check the signature with
          -> ByteString           -- ^ The encoded JWS
          -> Either JwtError Jws  -- ^ The decoded token if successful
rsaDecode key = decode (`rsaVerify` key)

sigTarget :: JwsAlg -> ByteString -> ByteString
sigTarget a payload = B.intercalate "." $ map B64.encode [encodeHeader $ defJwsHdr {jwsAlg = a}, payload]

type JwsVerifier = JwsAlg -> ByteString -> ByteString -> Bool

decode :: JwsVerifier -> ByteString -> Either JwtError Jws
decode verify jwt = do
    unless (BC.count '.' jwt == 2) $ Left $ BadDots 2
    let (hdrPayload, sig) = spanEndDot jwt
    sigBytes <- B64.decode sig
    [h, payload] <- mapM B64.decode $ BC.split '.' hdrPayload
    hdr <- case parseHeader h of
        Right (JwsH jwsHdr) -> return jwsHdr
        _                   -> Left BadHeader
    if verify (jwsAlg hdr) hdrPayload sigBytes
      then Right (hdr, payload)
      else Left BadSignature
  where
    spanEndDot bs = let (toDot, end) = BC.spanEnd (/= '.') bs
                    in  (B.init toDot, end)

