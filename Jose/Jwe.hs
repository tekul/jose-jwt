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
-- >>> let (Jwt jwt, g'') = rsaEncode g' RSA_OAEP A128GCM kPub "secret claims"
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
import Control.Error
import Crypto.PubKey.RSA (PrivateKey(..), PublicKey(..), generateBlinder, private_pub)
import Control.Monad.State.Strict
import Crypto.Random.API (CPRG)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Jose.Types
import qualified Jose.Internal.Base64 as B64
import Jose.Internal.Crypto
import Jose.Jwa
import Jose.Jwk

-- | Create a JWE using a JWK.
-- The key and algorithms must be consistent or an error
-- will be returned.
jwkEncode :: CPRG g
          => g                               -- ^ Random number generator
          -> JweAlg                          -- ^ Algorithm to use for key encryption
          -> Enc                             -- ^ Content encryption algorithm
          -> Jwk                             -- ^ The key to use to encrypt the content key
          -> Payload                         -- ^ The token content (claims or nested JWT)
          -> (Either JwtError Jwt, g)        -- ^ The encoded JWE if successful
jwkEncode rng a e jwk payload = case jwk of
    RsaPublicJwk kPub kid _ _ -> first Right $ rsaEncodeInternal rng (hdr kid) kPub bytes
    RsaPrivateJwk kPr kid _ _ -> first Right $ rsaEncodeInternal rng (hdr kid) (private_pub kPr) bytes
    _                         -> (Left $ KeyError "Only RSA JWKs can be used for encoding", rng)
  where
    hdr kid = defJweHdr {jweAlg = a, jweEnc = e, jweKid = kid, jweCty = contentType}
    (contentType, bytes) = case payload of
        Claims c       -> (Nothing, c)
        Nested (Jwt b) -> (Just "JWT", b)

-- | Creates a JWE.
rsaEncode :: CPRG g
          => g               -- ^ Random number generator
          -> JweAlg          -- ^ RSA algorithm to use (@RSA_OAEP@ or @RSA1_5@)
          -> Enc             -- ^ Content encryption algorithm
          -> PublicKey       -- ^ RSA key to encrypt with
          -> ByteString      -- ^ The JWT claims (content)
          -> (Jwt, g) -- ^ The encoded JWE and new generator
rsaEncode rng a e = rsaEncodeInternal rng (defJweHdr {jweAlg = a, jweEnc = e})

rsaEncodeInternal :: CPRG g
                  => g
                  -> JweHeader
                  -> PublicKey
                  -> ByteString
                  -> (Jwt, g)
rsaEncodeInternal rng h pubKey claims = (Jwt jwe, rng'')
  where
    a   = jweAlg h
    e   = jweEnc h
    hdr = encodeHeader h
    ((cmk, iv), rng') = generateCmkAndIV rng e
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
rsaDecode rng pk jwt = flip runState rng $ runEitherT $ do
    blinder <- state $ \g -> generateBlinder g (public_n $ private_pub pk)

    checkDots
    let components = BC.split '.' jwt
    let aad = head components
    [h, ek, providedIv, payload, sig] <- mapM B64.decode components
    hdr <- case parseHeader h of
        Right (JweH jweHdr) -> return jweHdr
        Right (JwsH _)      -> left (BadHeader "Header is for a JWS")
        Right UnsecuredH    -> left (BadHeader "Header is for an unsecured JWT")
        Left e              -> left e
    let alg = jweAlg hdr
        enc = jweEnc hdr
    (dummyCek, dummyIv) <- state $ \g -> generateCmkAndIV g enc
    let decryptedCek = either (const dummyCek) id $ rsaDecrypt (Just blinder) alg pk ek
        cek = if B.length decryptedCek == B.length dummyCek
                then decryptedCek
                else dummyCek
        iv  = if B.length providedIv == B.length dummyIv
                 then providedIv
                 else dummyIv
    claims <- decryptPayload enc cek iv aad sig payload
    return (hdr, claims)

  where
    checkDots = unless (BC.count '.' jwt == 4) $ left (BadDots 4)

