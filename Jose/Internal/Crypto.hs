{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_HADDOCK prune #-}

-- | Internal functions for encrypting and signing / decrypting
-- and verifying JWT content.

module Jose.Internal.Crypto
    ( hmacSign
    , hmacVerify
    , rsaSign
    , rsaVerify
    , rsaEncrypt
    , rsaDecrypt
    , encryptPayload
    , decryptPayload
    , generateCmkAndIV
    , pad
    , unpad
    )
where

import           Crypto.Cipher.Types (AuthTag(..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import           Crypto.Random (CPRG, cprgGenerate)
import qualified Crypto.Cipher.AES as AES
import           Crypto.PubKey.HashDescr
import           Crypto.MAC.HMAC (hmac)
import           Data.Byteable (constEqBytes)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.Serialize as Serialize
import qualified Data.Text as T
import           Data.Word (Word64, Word8)

import           Jose.Jwa
import           Jose.Types (JwtError(..))

-- | Sign a message with an HMAC key.
hmacSign :: JwsAlg      -- ^ HMAC algorithm to use
         -> ByteString  -- ^ Key
         -> ByteString  -- ^ The message/content
         -> Either JwtError ByteString  -- ^ HMAC output
hmacSign a k m = do
    hash <- maybe (Left $ BadAlgorithm $ T.pack $ "Not an HMAC algorithm: " ++ show a) return $ lookup a hmacHashes
    return $ hmac (hashFunction hash) 64 k m

-- | Verify the HMAC for a given message.
-- Returns false if the MAC is incorrect or the 'Alg' is not an HMAC.
hmacVerify :: JwsAlg      -- ^ HMAC Algorithm to use
           -> ByteString  -- ^ Key
           -> ByteString  -- ^ The message/content
           -> ByteString  -- ^ The signature to check
           -> Bool        -- ^ Whether the signature is correct
hmacVerify a key msg sig = either (const False) (`constEqBytes` sig) $ hmacSign a key msg

-- | Sign a message using an RSA private key.
--
-- The failure condition should only occur if the algorithm is not an RSA
-- algorithm, or the RSA key is too small, causing the padding of the
-- signature to fail. With real-world RSA keys this shouldn't happen in practice.
rsaSign :: Maybe RSA.Blinder  -- ^ RSA blinder
        -> JwsAlg             -- ^ Algorithm to use. Must be one of @RSA256@, @RSA384@ or @RSA512@
        -> RSA.PrivateKey     -- ^ Private key to sign with
        -> ByteString         -- ^ Message to sign
        -> Either JwtError ByteString    -- ^ The signature
rsaSign blinder a key msg = do
    hash <- maybe (Left $ BadAlgorithm $ T.pack $ "Not an RSA algorithm: " ++ show a) return $ lookupRSAHash a
    either (const $ Left BadCrypto) Right $ PKCS15.sign blinder hash key msg
  where

-- | Verify the signature for a message using an RSA public key.
--
-- Returns false if the check fails or if the 'Alg' value is not
-- an RSA signature algorithm.
rsaVerify :: JwsAlg        -- ^ The signature algorithm. Used to obtain the hash function.
          -> RSA.PublicKey -- ^ The key to check the signature with
          -> ByteString    -- ^ The message/content
          -> ByteString    -- ^ The signature to check
          -> Bool          -- ^ Whether the signature is correct
rsaVerify a key msg sig = case lookupRSAHash a of
    Just hash -> PKCS15.verify hash key msg sig
    Nothing   -> False

hmacHashes :: [(JwsAlg, HashDescr)]
hmacHashes = [(HS256, hashDescrSHA256), (HS384, hashDescrSHA384), (HS512, hashDescrSHA512)]

lookupRSAHash :: JwsAlg -> Maybe HashDescr
lookupRSAHash alg = case alg of
    RS256 -> Just hashDescrSHA256
    RS384 -> Just hashDescrSHA384
    RS512 -> Just hashDescrSHA512
    _     -> Nothing

-- | Generates the symmetric key (content management key) and IV
--
-- Used to encrypt a message.
generateCmkAndIV :: CPRG g
                 => g   -- ^ The random number generator
                 -> Enc -- ^ The encryption algorithm to be used
                 -> (B.ByteString, B.ByteString, g) -- ^ The key, IV and generator
generateCmkAndIV g e = (cmk, iv, g'')
  where
    (cmk, g') = cprgGenerate (keySize e) g
    (iv, g'') = cprgGenerate (ivSize e) g'  -- iv for aes gcm or cbc

keySize :: Enc -> Int
keySize A128GCM = 16
keySize A256GCM = 32
keySize A128CBC_HS256 = 32
keySize A256CBC_HS512 = 64

ivSize :: Enc -> Int
ivSize A128GCM = 12
ivSize A256GCM = 12
ivSize _       = 16

-- | Encrypts a message (typically a symmetric key) using RSA.
rsaEncrypt :: CPRG g
           => g                  -- ^ Random number generator
           -> JweAlg             -- ^ The algorithm (either @RSA1_5@ or @RSA_OAEP@)
           -> RSA.PublicKey      -- ^ The encryption key
           -> B.ByteString       -- ^ The message to encrypt
           -> (B.ByteString, g)  -- ^ The encrypted messaged and new generator
rsaEncrypt gen a pubKey content = (ct, g')
  where
    encrypt = case a of
        RSA1_5   -> PKCS15.encrypt gen
        RSA_OAEP -> OAEP.encrypt gen oaepParams
-- TODO: Check that we can't cause any errors here with our RSA public key
    (Right ct, g') = encrypt pubKey content

-- | Decrypts an RSA encrypted message.
rsaDecrypt :: Maybe RSA.Blinder
           -> JweAlg                        -- ^ The RSA algorithm to use
           -> RSA.PrivateKey                -- ^ The decryption key
           -> B.ByteString                  -- ^ The encrypted content
           -> Either JwtError B.ByteString  -- ^ The decrypted key
rsaDecrypt blinder a rsaKey jweKey = either (const $ Left BadCrypto) Right $ decrypt rsaKey jweKey
  where
    decrypt = case a of
        RSA1_5   -> PKCS15.decrypt blinder
        RSA_OAEP -> OAEP.decrypt blinder oaepParams

oaepParams :: OAEP.OAEPParams
oaepParams = OAEP.defaultOAEPParams (hashFunction hashDescrSHA1)

-- TODO: Need to check key length and IV are is valid for enc.

-- | Decrypt an AES encrypted message.
decryptPayload :: Enc        -- ^ Encryption algorithm
               -> ByteString -- ^ Content management key
               -> ByteString -- ^ IV
               -> ByteString -- ^ Additional authentication data
               -> ByteString -- ^ The integrity protection value to be checked
               -> ByteString -- ^ The encrypted JWT payload
               -> Either JwtError ByteString
decryptPayload e cek iv aad sig ct = do
    (plaintext, tag) <- case e of
        A128GCM        -> decryptedGCM
        A256GCM        -> decryptedGCM
        A128CBC_HS256  -> decryptedCBC 16 hashDescrSHA256
        A256CBC_HS512  -> decryptedCBC 32 hashDescrSHA512
    if tag == AuthTag sig
      then return plaintext
      else Left BadSignature
  where
    decryptedGCM = Right $ AES.decryptGCM (AES.initAES cek) iv aad ct

    decryptedCBC l h = do
      let (macKey, encKey) = B.splitAt (B.length cek `div` 2) cek
      let al = fromIntegral (B.length aad) * 8 :: Word64
      plaintext <- unpad $ AES.decryptCBC (AES.initAES encKey) iv ct
      let mac = authTag l h macKey $ B.concat [aad, iv, ct, Serialize.encode al]
      return (plaintext, mac)

-- | Encrypt a message using AES.
encryptPayload :: Enc                   -- ^ Encryption algorithm
               -> ByteString            -- ^ Content management key
               -> ByteString            -- ^ IV
               -> ByteString            -- ^ Additional authenticated data
               -> ByteString            -- ^ The message/JWT claims
               -> (ByteString, AuthTag) -- ^ Ciphertext claims and signature tag
encryptPayload e cek iv aad msg = case e of
    A128GCM        -> aesgcm
    A256GCM        -> aesgcm
    A128CBC_HS256  -> (aescbc, sig 16 hashDescrSHA256)
    A256CBC_HS512  -> (aescbc, sig 32 hashDescrSHA512)
  where
    aesgcm = AES.encryptGCM (AES.initAES cek) iv aad msg
    (macKey, encKey) = B.splitAt (B.length cek `div` 2) cek
    aescbc = AES.encryptCBC (AES.initAES encKey) iv (pad msg)
    al     = fromIntegral (B.length aad) * 8 :: Word64
    sig l h = authTag l h macKey $ B.concat [aad, iv, aescbc, Serialize.encode al]

authTag :: Int -> HashDescr -> ByteString -> ByteString -> AuthTag
authTag l h k m = AuthTag $ B.take l $ hmac (hashFunction h) 64 k m

unpad :: ByteString -> Either JwtError ByteString
unpad bs
    | padLen > 16 || padLen /= B.length padding = Left BadCrypto
    | B.any (/= padByte) padding = Left BadCrypto
    | otherwise = Right pt
  where
    len     = B.length bs
    padByte = B.last bs
    padLen  = fromIntegral padByte
    (pt, padding) = B.splitAt (len - padLen) bs

pad :: ByteString -> ByteString
pad bs = B.append bs padding
  where
    lastBlockSize = B.length bs `mod` 16
    padByte       = fromIntegral $ 16 - lastBlockSize :: Word8
    padding       = B.replicate (fromIntegral padByte) padByte

