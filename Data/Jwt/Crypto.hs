{-# LANGUAGE OverloadedStrings #-}

module Data.Jwt.Crypto where

import Data.ByteString (ByteString)
import Data.Word (Word64)
import qualified Data.Serialize as Serialize
import qualified Data.ByteString as B
import Data.Maybe (fromMaybe)
import Crypto.Cipher.Types (AuthTag(..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import Crypto.Random (CPRG, cprgGenerate)
import qualified Crypto.Cipher.AES as AES
import Crypto.PubKey.HashDescr
import Crypto.MAC.HMAC (hmac)
import Data.Text.Encoding (encodeUtf8)
import Data.Jwt.Types
import Data.Jwt.Internal


oaepParams = OAEP.defaultOAEPParams (hashFunction hashDescrSHA1)

hmacSign :: Alg         -- ^ HMAC algorithm to use
         -> ByteString  -- ^ Key
         -> ByteString  -- ^ The message/content
         -> ByteString  -- ^ HMAC output
hmacSign a k m =  hmac (hashFunction hash) 64 k m
  where
    hash = fromMaybe (error $ "Not an HMAC alg: " ++ show a) $ lookup a hmacHashes

hmacVerify :: Alg         -- ^ HMAC Algorithm to use
           -> ByteString  -- ^ Key
           -> ByteString  -- ^ The message/content
           -> ByteString  -- ^ The signature to check
           -> Bool        -- ^ Whether the signature is correct
hmacVerify a key msg sig = case lookup a hmacHashes of
    Just _  -> hmacSign a key msg == sig
    Nothing -> False

-- TODO: Check PKCS15.sign error conditions to see whether they apply
rsaSign :: Alg            -- ^ Algorithm to use
        -> RSA.PrivateKey -- ^ Private key to sign with
        -> ByteString     -- ^ Message to sign
        -> ByteString     -- ^ The signature
rsaSign a key = either (error "Signing failed") id . PKCS15.sign Nothing hash key
  where
    hash = fromMaybe (error $ "Not an RSA Algorithm " ++ show a) $ lookupRSAHash a

rsaVerify :: Alg
          -> RSA.PublicKey
          -> ByteString  -- ^ The message/content
          -> ByteString  -- ^ The signature to check
          -> Bool        -- ^ Whether the signature is correct
rsaVerify a key msg sig = case lookupRSAHash a of
    Just hash -> PKCS15.verify hash key msg sig
    Nothing   -> False

hmacHashes = [(HS256, hashDescrSHA256), (HS384, hashDescrSHA384), (HS512, hashDescrSHA512)]

lookupRSAHash alg = case alg of
    RS256 -> Just hashDescrSHA256
    RS384 -> Just hashDescrSHA384
    RS512 -> Just hashDescrSHA512
    _     -> Nothing

generateCmkAndIV :: CPRG g => g -> Enc -> (B.ByteString, B.ByteString, g)
generateCmkAndIV g e = (cmk, iv, g'')
  where
    (cmk, g') = cprgGenerate (keySize e) g
    (iv, g'') = cprgGenerate (ivSize e) g'  -- iv for aes gcm or cbc

keySize A128GCM = 16
keySize A256GCM = 32
keySize A128CBC_HS256 = 32
keySize A256CBC_HS512 = 64

ivSize A128GCM = 12
ivSize A256GCM = 12
ivSize _       = 16

rsaEncrypt :: CPRG g => g -> Alg -> RSA.PublicKey -> B.ByteString -> (B.ByteString, g)
rsaEncrypt gen a pubKey content = (ct, g')
  where
    encrypt = case a of
        RSA1_5   -> PKCS15.encrypt gen
        RSA_OAEP -> OAEP.encrypt gen oaepParams
        _        -> error "Not an RSA algorithm"
-- TODO: Check that we can't cause any errors here with our RSA public key
    (Right ct, g') = encrypt pubKey content

--rsaDecrypt :: Alg -> RSA.PrivateKey -> ByteString ->

decryptContentKey :: Alg -> RSA.PrivateKey -> B.ByteString -> Either JwtError B.ByteString
decryptContentKey a rsaKey jweKey = do
    decrypt <- decryptAlg
    either (\_ -> Left BadCrypto) Right $ decrypt rsaKey jweKey
  where
    decryptAlg = case a of
      RSA1_5   -> Right $ PKCS15.decrypt Nothing
      RSA_OAEP -> Right $ OAEP.decrypt Nothing oaepParams
      _        -> Left BadHeader

-- TODO: Need to check key length and IV are is valid for enc.
decryptPayload :: Enc        -- ^ Encryption algorithm
               -> ByteString -- ^ Content management key
               -> ByteString -- ^ IV
               -> ByteString -- ^ Additional authentication data
               -> ByteString -- ^ The integrity protection value to be checked
               -> ByteString -- ^ The encrypted JWT payload
               -> Either JwtError ByteString
decryptPayload e cek iv aad sig ct = do
    (plaintext, tag) <- case e of
        A128GCM -> decryptedGCM
        A256GCM -> decryptedGCM
        _       -> decryptedCBC
    if tag == AuthTag sig
      then return plaintext
      else Left BadSignature
  where
    decryptedGCM = Right $ AES.decryptGCM (AES.initAES cek) iv aad ct

    decryptedCBC = do
      let (macKey, encKey) = B.splitAt (B.length cek `div` 2) cek
      let al = fromIntegral (B.length aad) * 8 :: Word64
      plaintext <- unpad $ AES.decryptCBC (AES.initAES encKey) iv ct
      let mac = authTag (macAlg e) macKey $ B.concat [aad, iv, ct, Serialize.encode al]
      return (plaintext, mac)

encryptPayload :: Enc        -- ^ Encryption algorithm
               -> ByteString -- ^ Content management key
               -> ByteString -- ^ IV
               -> ByteString -- ^ Additional authenticated data
               -> ByteString -- ^ The message/JWT claims
               -> (ByteString, AuthTag) -- ^ Ciphertext claims and signature tag
encryptPayload e cek iv aad msg = case e of
    A128GCM -> aesgcm
    A256GCM -> aesgcm
    _       -> (aescbc, sig)
  where
    aesgcm = AES.encryptGCM (AES.initAES cek) iv aad msg
    (macKey, encKey) = B.splitAt (B.length cek `div` 2) cek
    aescbc = AES.encryptCBC (AES.initAES encKey) iv (pad msg)
    al     = fromIntegral (B.length aad) * 8 :: Word64
    sig = authTag (macAlg e) macKey $ B.concat [aad, iv, aescbc, Serialize.encode al]

authTag a k m = AuthTag $ B.take (tLen a) $ hmacSign a k m
  where
    tLen HS256 = 16
    tLen HS384 = 24
    tLen HS512 = 32

macAlg A128CBC_HS256 = HS256
macAlg A256CBC_HS512 = HS512

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
pad bs = B.append bs $ padding (B.length bs `mod` 16)
  where
    padding 15 = B.replicate 1 1
    padding 14 = B.replicate 2 2
    padding 13 = B.replicate 3 3
    padding 12 = B.replicate 4 4
    padding 11 = B.replicate 5 5
    padding 10 = B.replicate 6 6
    padding  9 = B.replicate 7 7
    padding  8 = B.replicate 8 8
    padding  7 = B.replicate 9 9
    padding  6 = B.replicate 10 10
    padding  5 = B.replicate 11 11
    padding  4 = B.replicate 12 12
    padding  3 = B.replicate 13 13
    padding  2 = B.replicate 14 14
    padding  1 = B.replicate 15 15
    padding  0 = B.replicate 16 16
