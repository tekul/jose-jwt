{-# LANGUAGE OverloadedStrings #-}

-- | JWE RSA encrypted token support.
--
-- Example usage:
--
-- >>> import Jose.Jwe
-- >>> import Jose.Jwa
-- >>> import Crypto.Random.AESCtr
-- >>> g <- makeSystem
-- >>> import Crypto.PubKey.RSA
-- >>> let ((kPub, kPr), g') = generate g 512 65537
-- >>> let (jwt, g'') = rsaEncode g' RSA_OAEP A128GCM kPub "secret claims"
-- >>> fst $ rsaDecode g'' kPr jwt
-- Right (JweHeader {jweAlg = RSA_OAEP, jweEnc = A128GCM, jweTyp = Nothing, jweCty = Nothing, jweZip = Nothing, jweKid = Nothing},"secret claims")

module Jose.Jwe
    ( jwkEncode
    , rsaEncode
    , rsaDecode
    )
where

import Control.Arrow (first)
import Crypto.Cipher.Types (AuthTag(..))
import Crypto.PubKey.RSA (PrivateKey(..), PublicKey(..), generateBlinder, private_pub)
import Crypto.Random.API (CPRG)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Jose.Types
import qualified Jose.Internal.Base64 as B64
import Jose.Internal.Crypto
import Jose.Jwa
import Jose.Jwk

jwkEncode :: CPRG g
          => g
          -> JweAlg
          -> Enc
          -> Jwk
          -> ByteString
          -> (Either JwtError ByteString, g)
jwkEncode rng a e jwk claims = case jwk of
    RsaPublicJwk kPub kid _ _ -> first Right $ rsaEncodeInternal rng (hdr kid) kPub claims
    RsaPrivateJwk kPr kid _ _ -> first Right $ rsaEncodeInternal rng (hdr kid) (private_pub kPr) claims
    _                         -> (Left $ KeyError "Only RSA JWKs can be used for encoding", rng)
  where
    hdr kid = defJweHdr {jweAlg = a, jweEnc = e, jweKid = kid}

-- | Creates a JWE.
rsaEncode :: CPRG g
          => g               -- ^ Random number generator
          -> JweAlg          -- ^ RSA algorithm to use (@RSA_OAEP@ or @RSA1_5@)
          -> Enc             -- ^ Content encryption algorithm
          -> PublicKey       -- ^ RSA key to encrypt with
          -> ByteString      -- ^ The JWT claims (content)
          -> (ByteString, g) -- ^ The encoded JWE and new generator
rsaEncode rng a e = rsaEncodeInternal rng (defJweHdr {jweAlg = a, jweEnc = e})

rsaEncodeInternal :: CPRG g
                  => g
                  -> JweHeader
                  -> PublicKey
                  -> ByteString
                  -> (ByteString, g)
rsaEncodeInternal rng h pubKey claims = (jwe, rng'')
  where
    a   = jweAlg h
    e   = jweEnc h
    hdr = encodeHeader h
    (cmk, iv, rng') = generateCmkAndIV rng e
    (jweKey, rng'') = rsaEncrypt rng' a pubKey cmk
    aad = B64.encode hdr
    (ct, AuthTag sig) = encryptPayload e cmk iv aad claims
    jwe = B.intercalate "." $ map B64.encode [hdr, jweKey, iv, ct, sig]


-- | Decrypts a JWE.
rsaDecode :: CPRG g
          => g
          -> PrivateKey               -- ^ Decryption key
          -> ByteString               -- ^ The encoded JWE
          -> (Either JwtError Jwe, g) -- ^ The decoded JWT, unless an error occurs
rsaDecode rng pk jwt = (decode blinder, rng')
  where
    (blinder, rng') = generateBlinder rng (public_n $ private_pub pk)

    decode b = do
        checkDots
        let components = BC.split '.' jwt
        let aad = head components
        [h, ek, iv, payload, sig] <- mapM B64.decode components
        hdr <- case parseHeader h of
            Right (JweH jweHdr) -> return jweHdr
            Right (JwsH _)      -> Left (BadHeader "Header is for a JWS")
            Left e              -> Left e
        let alg = jweAlg hdr
        cek    <- rsaDecrypt (Just b) alg pk ek
        claims <- decryptPayload (jweEnc hdr) cek iv aad sig payload
        return (hdr, claims)

    checkDots = case BC.count '.' jwt of
                    4 -> Right ()
                    _ -> Left $ BadDots 4

