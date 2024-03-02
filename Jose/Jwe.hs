{-# LANGUAGE OverloadedStrings #-}

-- | JWE encrypted token support.
--
-- To create a JWE, you need to select two algorithms. One is an AES algorithm
-- used to encrypt the content of your token (for example, @A128GCM@), for which
-- a single-use key is generated internally. The second is used to encrypt
-- this content-encryption key and can be either an RSA or AES-keywrap algorithm.
-- You need to generate a suitable key to use with this, or load one from storage.
--
-- AES is much faster and creates shorter tokens, but both the encoder and decoder
-- of the token need to have a copy of the key, which they must keep secret. With
-- RSA anyone can send you a JWE if they have a copy of your public key.
--
-- In the example below, we show encoding and decoding using a 2048 bit RSA key pair
-- (256 bytes). If using RSA, use one of the @RSA_OAEP@ algorithms. @RSA1_5@ is
-- deprecated due to <https://robotattack.org/ known vulnerabilities>.
--
-- >>> import Jose.Jwe
-- >>> import Jose.Jwa
-- >>> import Jose.Jwk (generateRsaKeyPair, generateSymmetricKey, KeyUse(Enc), KeyId)
-- >>> (kPub, kPr) <- generateRsaKeyPair 256 (KeyId "My RSA Key") Enc Nothing
-- >>> Right (Jwt jwt) <- jwkEncode RSA_OAEP A128GCM kPub (Claims "secret claims")
-- >>> Right (Jwe (hdr, claims)) <- jwkDecode kPr jwt
-- >>> claims
-- "secret claims"
--
-- Using 128-bit AES keywrap is very similar, the main difference is that
-- we generate a 128-bit symmetric key (16 bytes):
--
-- >>> aesKey <- generateSymmetricKey 16 (KeyId "My Keywrap Key") Enc Nothing
-- >>> Right (Jwt jwt) <- jwkEncode A128KW A128GCM aesKey (Claims "more secret claims")
-- >>> Right (Jwe (hdr, claims)) <- jwkDecode aesKey jwt
-- >>> claims
-- "more secret claims"

module Jose.Jwe
    ( jwkEncode
    , jwkDecode
    , rsaEncode
    , rsaDecode
    )
where

import Control.Monad.Trans (lift)
import Control.Monad.Trans.Except
import Crypto.Cipher.Types (AuthTag(..))
import Crypto.PubKey.RSA (PrivateKey(..), PublicKey(..), generateBlinder, private_pub)
import Crypto.Random (MonadRandom)
import qualified Data.Aeson as A
import Data.ByteArray (ByteArray, ScrubbedBytes)
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Maybe (isNothing)
import Jose.Types
import qualified Jose.Internal.Base64 as B64
import Jose.Internal.Crypto
import Jose.Jwa
import Jose.Jwk
import qualified Jose.Internal.Parser as P

-- | Create a JWE using a JWK.
-- The key and algorithms must be consistent or an error
-- will be returned.
jwkEncode :: MonadRandom m
    => JweAlg                          -- ^ Algorithm to use for key encryption
    -> Enc                             -- ^ Content encryption algorithm
    -> Jwk                             -- ^ The key to use to encrypt the content key
    -> Payload                         -- ^ The token content (claims or nested JWT)
    -> m (Either JwtError Jwt)         -- ^ The encoded JWE if successful
jwkEncode a e jwk payload = runExceptT $ case jwk of
    RsaPublicJwk kPub kid _ _ -> doEncode (hdr kid) e (doRsa kPub) bytes
    RsaPrivateJwk kPr kid _ _ -> doEncode (hdr kid) e (doRsa (private_pub kPr)) bytes
    SymmetricJwk  kek kid _ _ -> doEncode (hdr kid) e (ExceptT .  return . keyWrap a (BA.convert kek)) bytes
    _                         -> throwE $ KeyError "JWK cannot encode a JWE"
  where
    doRsa kPub = ExceptT . rsaEncrypt kPub a
    hdr :: Maybe KeyId -> B.ByteString
    hdr kid = BL.toStrict $
        BL.concat
            [ "{\"alg\":"
            , A.encode a
            , ",\"enc\":"
            , A.encode e
            , maybe "" (\c -> BL.concat [",\"cty\":\"", c, "\"" ]) contentType
            , if isNothing kid then "" else BL.concat [",\"kid\":", A.encode kid ]
            , "}"
            ]

    (contentType, bytes) = case payload of
        Claims c       -> (Nothing, c)
        Nested (Jwt b) -> (Just "JWT", b)


-- | Try to decode a JWE using a JWK.
-- If the key type does not match the content encoding algorithm,
-- an error will be returned.
jwkDecode :: MonadRandom m
    => Jwk
    -> ByteString
    -> m (Either JwtError JwtContent)
jwkDecode jwk jwt = runExceptT $ case jwk of
    RsaPrivateJwk kPr _ _ _ -> do
        blinder <- lift $ generateBlinder (public_n $ private_pub kPr)
        e <- doDecode (rsaDecrypt (Just blinder) kPr) jwt
        return (Jwe e)
    SymmetricJwk kb   _ _ _ -> fmap Jwe (doDecode (keyUnwrap (BA.convert kb)) jwt)
    UnsupportedJwk _ -> throwE (KeyError "Unsupported JWK cannot be used to decode JWE")
    _ -> throwE $ KeyError "This JWK cannot decode a JWE"


doDecode :: MonadRandom m
    => (JweAlg -> ByteString -> Either JwtError ScrubbedBytes)
    -> ByteString
    -> ExceptT JwtError m Jwe
doDecode decodeCek jwt = do
    encodedJwt <- ExceptT (return (P.parseJwt jwt))
    case encodedJwt of
        P.DecodableJwe hdr (P.EncryptedCEK ek) iv (P.Payload payload) tag (P.AAD aad) -> do
            let alg = jweAlg hdr
                enc = jweEnc hdr
            (dummyCek, _) <- lift $ generateCmkAndIV enc
            let decryptedCek = either (const dummyCek) id $ decodeCek alg ek
                cek = if BA.length decryptedCek == BA.length dummyCek
                        then decryptedCek
                        else dummyCek
            claims <- maybe (throwE BadCrypto) return $ decryptPayload enc cek iv aad tag payload
            return (hdr, claims)

        _ -> throwE (BadHeader "Content is not a JWE")


doEncode :: (MonadRandom m, ByteArray ba)
    => ByteString
    -> Enc
    -> (ScrubbedBytes -> ExceptT JwtError m ByteString)
    -> ba
    -> ExceptT JwtError m Jwt
doEncode hdr e encryptKey claims = do
    (cmk, iv) <- lift (generateCmkAndIV e)
    let aad = B64.encode hdr
        (signature, ciphertext) = case encryptPayload e cmk iv aad claims of
                        Just (AuthTag sig, ct) -> (sig, ct)
                        Nothing -> error "encryptPayload failed! Shouldn't happen with valid key and iv"
    jweKey <- encryptKey cmk
    let jwe = B.intercalate "." $ map B64.encode [hdr, jweKey, BA.convert iv, BA.convert ciphertext, BA.convert signature]
    return (Jwt jwe)

-- | Creates a JWE with the content key encoded using RSA.
rsaEncode :: MonadRandom m
    => JweAlg          -- ^ RSA algorithm to use (@RSA_OAEP@ or @RSA1_5@)
    -> Enc             -- ^ Content encryption algorithm
    -> PublicKey       -- ^ RSA key to encrypt with
    -> ByteString      -- ^ The JWT claims (content)
    -> m (Either JwtError Jwt) -- ^ The encoded JWE
rsaEncode a e kPub claims = runExceptT $ doEncode hdr e (ExceptT . rsaEncrypt kPub a) claims
  where
    hdr = BL.toStrict $ BL.concat ["{\"alg\":", A.encode a, ",", "\"enc\":", A.encode e, "}"]


-- | Decrypts a JWE.
rsaDecode :: MonadRandom m
    => PrivateKey               -- ^ Decryption key
    -> ByteString               -- ^ The encoded JWE
    -> m (Either JwtError Jwe)  -- ^ The decoded JWT, unless an error occurs
rsaDecode pk jwt = runExceptT $ do
    blinder <- lift $ generateBlinder (public_n $ private_pub pk)
    doDecode (rsaDecrypt (Just blinder) pk) jwt
