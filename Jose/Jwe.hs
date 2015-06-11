{-# LANGUAGE OverloadedStrings #-}

-- | JWE RSA encrypted token support.
--
-- Example usage:
--
-- >>> import Jose.Jwe
-- >>> import Jose.Jwa
-- >>> import Crypto.Random
-- >>> g <- drgNew
-- >>> import Crypto.PubKey.RSA
-- >>> let ((kPub, kPr), g') = withDRG g (generate 512 65537)
-- >>> let (Right (Jwt jwt), g'') = withDRG g' (rsaEncode RSA_OAEP A128GCM kPub "secret claims")
-- >>> fst $ withDRG g'' (rsaDecode kPr jwt)
-- Right (JweHeader {jweAlg = RSA_OAEP, jweEnc = A128GCM, jweTyp = Nothing, jweCty = Nothing, jweZip = Nothing, jweKid = Nothing},"secret claims")

module Jose.Jwe
    ( jwkEncode
    , rsaEncode
    , rsaDecode
    )
where

import Control.Monad (unless)
import Control.Monad.Trans (lift)
import Control.Monad.Trans.Either
import Crypto.Cipher.Types (AuthTag(..))
import Crypto.PubKey.RSA (PrivateKey(..), PublicKey(..), generateBlinder, private_pub)
import Crypto.Random (MonadRandom)
import qualified Data.ByteArray as BA
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
jwkEncode :: MonadRandom m
          => JweAlg                          -- ^ Algorithm to use for key encryption
          -> Enc                             -- ^ Content encryption algorithm
          -> Jwk                             -- ^ The key to use to encrypt the content key
          -> Payload                         -- ^ The token content (claims or nested JWT)
          -> m (Either JwtError Jwt)         -- ^ The encoded JWE if successful
jwkEncode a e jwk payload = runEitherT $ case jwk of
    RsaPublicJwk kPub kid _ _ -> doEncode (hdr kid) (doRsa kPub) bytes
    RsaPrivateJwk kPr kid _ _ -> doEncode (hdr kid) (doRsa (private_pub kPr)) bytes
    SymmetricJwk  kek kid _ _ -> doEncode (hdr kid) (hoistEither . keyWrap a kek) bytes
    _                         -> left $ KeyError "Only RSA JWKs can be used for encoding"
  where
    doRsa kPub = EitherT . rsaEncrypt a kPub
    hdr kid = defJweHdr {jweAlg = a, jweEnc = e, jweKid = kid, jweCty = contentType}
    (contentType, bytes) = case payload of
        Claims c       -> (Nothing, c)
        Nested (Jwt b) -> (Just "JWT", b)

doEncode :: MonadRandom m
    => JweHeader
    -> (ByteString -> EitherT JwtError m ByteString)
    -> ByteString
    -> EitherT JwtError m Jwt
doEncode h encryptKey claims = do
    (cmk, iv) <- lift (generateCmkAndIV e)
    let Just (AuthTag sig, ct) = encryptPayload e cmk iv aad claims
    jweKey <- encryptKey cmk
    let jwe = B.intercalate "." $ map B64.encode [hdr, jweKey, iv, ct, BA.convert sig]
    return (Jwt jwe)
  where
    e   = jweEnc h
    hdr = encodeHeader h
    aad = B64.encode hdr

-- | Creates a JWE with the content key encoded using RSA.
rsaEncode :: MonadRandom m
    => JweAlg          -- ^ RSA algorithm to use (@RSA_OAEP@ or @RSA1_5@)
    -> Enc             -- ^ Content encryption algorithm
    -> PublicKey       -- ^ RSA key to encrypt with
    -> ByteString      -- ^ The JWT claims (content)
    -> m (Either JwtError Jwt) -- ^ The encoded JWE
rsaEncode a e kPub claims = runEitherT $ doEncode (defJweHdr {jweAlg = a, jweEnc = e}) (EitherT . rsaEncrypt a kPub) claims

-- | Decrypts a JWE.
rsaDecode :: MonadRandom m
          => PrivateKey               -- ^ Decryption key
          -> ByteString               -- ^ The encoded JWE
          -> m (Either JwtError Jwe)  -- ^ The decoded JWT, unless an error occurs
rsaDecode pk jwt = runEitherT $ do
    blinder <- lift $ generateBlinder (public_n $ private_pub pk)
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
    (dummyCek, dummyIv) <- lift $ generateCmkAndIV enc
    let decryptedCek = either (const dummyCek) id $ rsaDecrypt (Just blinder) alg pk ek
        cek = if B.length decryptedCek == B.length dummyCek
                then decryptedCek
                else dummyCek
        iv  = if B.length providedIv == B.length dummyIv
                 then providedIv
                 else dummyIv
        authTag = AuthTag $ BA.convert sig
    claims <- maybe (left BadCrypto) return $ decryptPayload enc cek iv aad authTag payload
    return (hdr, claims)

  where
    checkDots = unless (BC.count '.' jwt == 4) $ left (BadDots 4)
