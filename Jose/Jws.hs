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
    ( jwkEncode
    , hmacEncode
    , hmacDecode
    , rsaEncode
    , rsaDecode
    , ecDecode
    )
where

import Control.Applicative
import Control.Monad (unless)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.PubKey.RSA (PrivateKey(..), PublicKey(..), generateBlinder)
import Crypto.Random (CPRG)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Jose.Types
import qualified Jose.Internal.Base64 as B64
import Jose.Internal.Crypto
import Jose.Jwa
import Jose.Jwk (Jwk (..))

-- | Create a JWS signed with a JWK.
-- The key and algorithm must be consistent or an error
-- will be returned.
jwkEncode :: (CPRG g)
          => g
          -> JwsAlg                          -- ^ The algorithm to use
          -> Jwk                             -- ^ The key to sign with
          -> ByteString                      -- ^ The public JWT claims
          -> (Either JwtError ByteString, g) -- ^ The encoded token, if successful
jwkEncode rng a key payload = case key of
    RsaPrivateJwk kPr kid _ _ -> rsaEncodeInternal rng a kPr (sigTarget a kid payload)
    SymmetricJwk  k   kid _ _ -> (hmacEncodeInternal a k (sigTarget a kid payload), rng)
    _                         -> (Left $ BadAlgorithm "EC signing is not supported", rng)

-- | Create a JWS with an HMAC for validation.
hmacEncode :: JwsAlg       -- ^ The MAC algorithm to use
           -> ByteString   -- ^ The MAC key
           -> ByteString   -- ^ The public JWT claims (token content)
           -> Either JwtError ByteString   -- ^ The encoded JWS token
hmacEncode a key payload = hmacEncodeInternal a key (sigTarget a Nothing payload)

hmacEncodeInternal :: JwsAlg
                   -> ByteString
                   -> ByteString
                   -> Either JwtError ByteString
hmacEncodeInternal a key st = (\mac -> B.concat [st, ".", B64.encode mac]) <$> hmacSign a key st

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
rsaEncode rng a pk payload = rsaEncodeInternal rng a pk (sigTarget a Nothing payload)

rsaEncodeInternal :: CPRG g
                  => g
                  -> JwsAlg
                  -> PrivateKey
                  -> ByteString
                  -> (Either JwtError ByteString, g)
rsaEncodeInternal rng a pk st = (sign blinder, rng')
  where
    (blinder, rng') = generateBlinder rng (public_n $ private_pub pk)

    sign b = case rsaSign (Just b) a pk st of
        Right sig -> Right $ B.concat [st, ".", B64.encode sig]
        err       -> err

-- | Decode and validate an RSA signed JWS.
rsaDecode :: PublicKey            -- ^ The key to check the signature with
          -> ByteString           -- ^ The encoded JWS
          -> Either JwtError Jws  -- ^ The decoded token if successful
rsaDecode key = decode (`rsaVerify` key)


-- | Decode and validate an EC signed JWS
ecDecode :: ECDSA.PublicKey       -- ^ The key to check the signature with
         -> ByteString            -- ^ The encoded JWS
         -> Either JwtError Jws   -- ^ The decoded token if successful
ecDecode key = decode (`ecVerify` key)

sigTarget :: JwsAlg -> Maybe KeyId -> ByteString -> ByteString
sigTarget a kid payload = B.intercalate "." $ map B64.encode [encodeHeader $ defJwsHdr {jwsAlg = a, jwsKid = kid}, payload]

type JwsVerifier = JwsAlg -> ByteString -> ByteString -> Bool

decode :: JwsVerifier -> ByteString -> Either JwtError Jws
decode verify jwt = do
    unless (BC.count '.' jwt == 2) $ Left $ BadDots 2
    let (hdrPayload, sig) = spanEndDot jwt
    sigBytes <- B64.decode sig
    [h, payload] <- mapM B64.decode $ BC.split '.' hdrPayload
    hdr <- case parseHeader h of
        Right (JwsH jwsHdr) -> return jwsHdr
        Right (JweH _)      -> Left (BadHeader "Header is for a JWE")
        Left e              -> Left e
    if verify (jwsAlg hdr) hdrPayload sigBytes
      then Right (hdr, payload)
      else Left BadSignature
  where
    spanEndDot bs = let (toDot, end) = BC.spanEnd (/= '.') bs
                    in  (B.init toDot, end)

