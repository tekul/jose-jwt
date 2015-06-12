{-# LANGUAGE OverloadedStrings, FlexibleContexts #-}
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
    , ecVerify
    , encryptPayload
    , decryptPayload
    , generateCmkAndIV
    , keyWrap
    , keyUnwrap
    , pad
    , unpad
    )
where

import           Control.Monad.Error
import           Crypto.Error
import           Crypto.Cipher.AES
import           Crypto.Cipher.Types
import           Crypto.Hash.Algorithms
import           Crypto.Number.Serialize (os2ip)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import           Crypto.Random (MonadRandom, getRandomBytes)
import           Crypto.PubKey.HashDescr
import           Crypto.MAC.HMAC (HMAC (..), hmac)
import           Data.Bits (xor)
import qualified Data.ByteArray as BA
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Either.Combinators
import qualified Data.Serialize as Serialize
import qualified Data.Text as T
import           Data.Word (Word64, Word8)

import           Jose.Jwa
import           Jose.Types (JwtError(..))

-- | Sign a message with an HMAC key.
hmacSign :: JwsAlg      -- ^ HMAC algorithm to use
         -> ByteString  -- ^ Key
         -> ByteString  -- ^ The message/content
         -> Either JwtError ByteString -- ^ HMAC output
hmacSign a k m = case a of
    HS256 -> Right $ BA.convert (hmac k m :: HMAC SHA256)
    HS384 -> Right $ BA.convert (hmac k m :: HMAC SHA384)
    HS512 -> Right $ BA.convert (hmac k m :: HMAC SHA512)
    _     -> Left $ BadAlgorithm $ T.pack $ "Not an HMAC algorithm: " ++ show a

-- | Verify the HMAC for a given message.
-- Returns false if the MAC is incorrect or the 'Alg' is not an HMAC.
hmacVerify :: JwsAlg      -- ^ HMAC Algorithm to use
           -> ByteString  -- ^ Key
           -> ByteString  -- ^ The message/content
           -> ByteString  -- ^ The signature to check
           -> Bool        -- ^ Whether the signature is correct
hmacVerify a key msg sig = either (const False) (`BA.constEq` sig) $ hmacSign a key msg

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
rsaSign blinder a key msg = case a of
    RS256 -> go hashDescrSHA256
    RS384 -> go hashDescrSHA384
    RS512 -> go hashDescrSHA512
    _     -> Left . BadAlgorithm . T.pack $ "Not an RSA algorithm: " ++ show a
  where
    go h = either (const $ Left BadCrypto) Right $ PKCS15.sign blinder h key msg

-- | Verify the signature for a message using an RSA public key.
--
-- Returns false if the check fails or if the 'Alg' value is not
-- an RSA signature algorithm.
rsaVerify :: JwsAlg        -- ^ The signature algorithm. Used to obtain the hash function.
          -> RSA.PublicKey -- ^ The key to check the signature with
          -> ByteString    -- ^ The message/content
          -> ByteString    -- ^ The signature to check
          -> Bool          -- ^ Whether the signature is correct
rsaVerify a key msg sig = case a of
    RS256 -> go hashDescrSHA256
    RS384 -> go hashDescrSHA384
    RS512 -> go hashDescrSHA512
    _     -> False
  where
    go h = PKCS15.verify h key msg sig

-- | Verify the signature for a message using an EC public key.
--
-- Returns false if the check fails or if the 'Alg' value is not
-- an EC signature algorithm.
ecVerify :: JwsAlg          -- ^ The signature algorithm. Used to obtain the hash function.
         -> ECDSA.PublicKey -- ^ The key to check the signature with
         -> ByteString      -- ^ The message/content
         -> ByteString      -- ^ The signature to check
         -> Bool            -- ^ Whether the signature is correct
ecVerify a key msg sig = case a of
    ES256 -> go SHA256
    ES384 -> go SHA384
    ES512 -> go SHA512
    _     -> False
  where
    (r, s) = B.splitAt (B.length sig `div` 2) sig
    ecSig  = ECDSA.Signature (os2ip r) (os2ip s)
    go h   = ECDSA.verify h key ecSig msg

-- | Generates the symmetric key (content management key) and IV
--
-- Used to encrypt a message.
generateCmkAndIV :: MonadRandom m
                 => Enc -- ^ The encryption algorithm to be used
                 -> m (B.ByteString, B.ByteString) -- ^ The key, IV
generateCmkAndIV e = do
    cmk <- getRandomBytes (keySize e)
    iv  <- getRandomBytes (ivSize e)   -- iv for aes gcm or cbc
    return (cmk, iv)
  where
    keySize A128GCM = 16
    keySize A192GCM = 24
    keySize A256GCM = 32
    keySize A128CBC_HS256 = 32
    keySize A192CBC_HS384 = 48
    keySize A256CBC_HS512 = 64

    ivSize A128GCM = 12
    ivSize A192GCM = 12
    ivSize A256GCM = 12
    ivSize _       = 16

-- | Encrypts a message (typically a symmetric key) using RSA.
rsaEncrypt :: MonadRandom m
    => RSA.PublicKey      -- ^ The encryption key
    -> JweAlg             -- ^ The algorithm (either @RSA1_5@ or @RSA_OAEP@)
    -> B.ByteString       -- ^ The message to encrypt
    -> m (Either JwtError B.ByteString)     -- ^ The encrypted message
rsaEncrypt k a bs = case a of
    RSA1_5   -> mapErr (PKCS15.encrypt k bs)
    RSA_OAEP -> mapErr (OAEP.encrypt (OAEP.defaultOAEPParams SHA1) k bs)
    _        -> return (Left (BadAlgorithm "Not an RSA algorithm"))
  where
    mapErr = fmap (mapLeft (const BadCrypto))

-- | Decrypts an RSA encrypted message.
rsaDecrypt :: Maybe RSA.Blinder
           -> RSA.PrivateKey                -- ^ The decryption key
           -> JweAlg                        -- ^ The RSA algorithm to use
           -> B.ByteString                  -- ^ The encrypted content
           -> Either JwtError B.ByteString  -- ^ The decrypted key
rsaDecrypt blinder rsaKey a jweKey = case a of
    RSA1_5   -> mapErr (PKCS15.decrypt blinder rsaKey jweKey)
    RSA_OAEP -> mapErr (OAEP.decrypt blinder (OAEP.defaultOAEPParams SHA1) rsaKey jweKey)
    _        -> Left (BadAlgorithm "Not an RSA algorithm")
  where
    mapErr = mapLeft (const BadCrypto)

-- Dummy type to constrain Cipher type
data C c = C

initCipher :: BlockCipher c => C c -> B.ByteString -> Maybe c
initCipher _ k = maybeCryptoError $ cipherInit k

-- | Decrypt an AES encrypted message.
decryptPayload :: Enc        -- ^ Encryption algorithm
               -> ByteString -- ^ Content management key
               -> ByteString -- ^ IV
               -> ByteString -- ^ Additional authentication data
               -> AuthTag    -- ^ The integrity protection value to be checked
               -> ByteString -- ^ The encrypted JWT payload
               -> Maybe ByteString
decryptPayload enc cek iv aad sig ct = case enc of
    A128GCM       -> doGCM (C :: C AES128)
    A192GCM       -> doGCM (C :: C AES192)
    A256GCM       -> doGCM (C :: C AES256)
    A128CBC_HS256 -> doCBC (C :: C AES128) SHA256 16
    A192CBC_HS384 -> doCBC (C :: C AES192) SHA384 24
    A256CBC_HS512 -> doCBC (C :: C AES256) SHA512 32
  where
    (cbcMacKey, cbcEncKey) = B.splitAt (B.length cek `div` 2) cek
    al = fromIntegral (B.length aad) * 8 :: Word64

    doGCM :: BlockCipher c => C c -> Maybe ByteString
    doGCM c = do
        cipher <- initCipher c cek
        aead <- maybeCryptoError (aeadInit AEAD_GCM cipher iv)
        aeadSimpleDecrypt aead aad ct (AuthTag $ BA.convert sig)

    doCBC :: (HashAlgorithm a, BlockCipher c) => C c -> a -> Int -> Maybe ByteString
    doCBC c a tagLen = do
        checkMac a tagLen
        cipher <- initCipher c cbcEncKey
        iv'    <- makeIV iv
        unless (B.length ct `mod` blockSize cipher == 0) Nothing
        unpad $ cbcDecrypt cipher iv' ct

    checkMac :: HashAlgorithm a => a -> Int -> Maybe ()
    checkMac a l = do
        let mac = BA.take l $ BA.convert $ doMac a :: BA.Bytes
        unless (sig `BA.constEq` mac) Nothing

    doMac :: HashAlgorithm a => a -> HMAC a
    doMac _ = hmac cbcMacKey $ B.concat [aad, iv, ct, Serialize.encode al]

-- | Encrypt a message using AES.
encryptPayload :: Enc                   -- ^ Encryption algorithm
               -> ByteString            -- ^ Content management key
               -> ByteString            -- ^ IV
               -> ByteString            -- ^ Additional authenticated data
               -> ByteString            -- ^ The message/JWT claims
               -> Maybe (AuthTag, ByteString) -- ^ Ciphertext claims and signature tag
encryptPayload e cek iv aad msg = case e of
    A128GCM       -> doGCM (C :: C AES128)
    A192GCM       -> doGCM (C :: C AES192)
    A256GCM       -> doGCM (C :: C AES256)
    A128CBC_HS256 -> doCBC (C :: C AES128) SHA256 16
    A192CBC_HS384 -> doCBC (C :: C AES192) SHA384 24
    A256CBC_HS512 -> doCBC (C :: C AES256) SHA512 32
  where
    (cbcMacKey, cbcEncKey) = B.splitAt (B.length cek `div` 2) cek
    al = fromIntegral (B.length aad) * 8 :: Word64

    doGCM :: BlockCipher c => C c -> Maybe (AuthTag, ByteString)
    doGCM c = do
        cipher <- initCipher c cek
        aead <- maybeCryptoError (aeadInit AEAD_GCM cipher iv)
        return $ aeadSimpleEncrypt aead aad msg 16

    doCBC :: (HashAlgorithm a, BlockCipher c) => C c -> a -> Int -> Maybe (AuthTag, ByteString)
    doCBC c a tagLen = do
        cipher <- initCipher c cbcEncKey
        iv'    <- makeIV iv
        let ct = cbcEncrypt cipher iv' (pad msg)
            mac = doMac a ct
            tag = BA.take tagLen (BA.convert mac)
        return (AuthTag tag, ct)

    doMac :: HashAlgorithm a => a -> ByteString -> HMAC a
    doMac _ ct = hmac cbcMacKey $ B.concat [aad, iv, ct, Serialize.encode al]

unpad :: ByteString -> Maybe ByteString
unpad bs
    | padLen > 16 || padLen /= B.length padding = Nothing
    | B.any (/= padByte) padding = Nothing
    | otherwise = return pt
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

-- Key wrapping and unwrapping functions

-- | <https://tools.ietf.org/html/rfc3394#section-2.2.1>
keyWrap :: JweAlg -> ByteString -> ByteString -> Either JwtError ByteString
keyWrap alg kek cek = case alg of
    A128KW -> doKeyWrap (C :: C AES128)
    A192KW -> doKeyWrap (C :: C AES192)
    A256KW -> doKeyWrap (C :: C AES256)
    _      -> Left (BadAlgorithm "Not a keywrap algorithm")
  where
    l = B.length cek
    n = l `div` 8
    iv = BA.replicate 8 166 :: ByteString

    doKeyWrap c = do
        when (l < 16 || l `mod` 8 /= 0) (Left (KeyError "Invalid content key"))
        cipher <- maybe (Left (KeyError "cipher initialization failed")) return $ initCipher c kek
        let p = toBlocks cek
            (r0, r) = foldl (doRound (ecbEncrypt cipher) 1) (iv, p) [0..5]
        Right $ B.concat (r0 : r)

    doRound _ _  (a, []) _ = (a, [])
    doRound enc i (a, r:rs) j =
        let b  = enc $ B.concat [a, r]
            t  = fromIntegral ((n*j) + i) :: Word8
            a' = txor t (B.take 8 b)
            r' = B.drop 8 b
            next = doRound enc (i+1) (a', rs) j
        in (fst next, r' : snd next)

    txor t b = B.snoc (B.init b) (B.last b `xor` t)

toBlocks :: ByteString -> [ByteString]
toBlocks bytes
    | bytes == B.empty = []
    | otherwise    = let (b, bs') = B.splitAt 8 bytes
                        in  b : toBlocks bs'

keyUnwrap :: ByteString -> JweAlg -> ByteString -> Either JwtError ByteString
keyUnwrap kek alg encK = case alg of
    A128KW -> doUnWrap (C :: C AES128)
    A192KW -> doUnWrap (C :: C AES192)
    A256KW -> doUnWrap (C :: C AES256)
    _      -> Left (BadAlgorithm "Not a keywrap algorithm")
  where
    l = B.length encK
    n = (l `div` 8) - 1
    iv = BA.replicate 8 166 :: ByteString

    doUnWrap c = do
        when (l < 24 || l `mod` 8 /= 0) (Left BadCrypto)
        cipher <- maybe (Left BadCrypto) return $ initCipher c kek
        let r = toBlocks encK
            (p0, p) = foldl (doRound (ecbDecrypt cipher) n) (head r, reverse (tail r)) (reverse [0..5])
        unless (p0 == iv) (Left BadCrypto)
        Right $ B.concat (reverse p)

    doRound _ _  (a, []) _ = (a, [])
    doRound dec i (a, r:rs) j =
        let b  = dec $ B.concat [txor t a, r]
            t  = fromIntegral ((n*j) + i) :: Word8
            a' = B.take 8 b
            r' = B.drop 8 b
            next = doRound dec (i-1) (a', rs) j
        in (fst next, r' : snd next)

    txor t b = B.snoc (B.init b) (B.last b `xor` t)
