{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
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
    , ecSign
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


import           Control.Applicative
import           Control.Monad (when, unless)
import           Crypto.Error
import           Crypto.Cipher.AES
import           Crypto.Cipher.Types hiding (IV)
import           Crypto.Hash.Algorithms
import           Crypto.Number.Serialize (os2ip, i2ospOf_)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import           Crypto.Random (MonadRandom, getRandomBytes)
import           Crypto.MAC.HMAC (HMAC (..), hmac)
import           Data.Bits (xor)
import           Data.ByteArray (ByteArray, ScrubbedBytes)
import qualified Data.ByteArray as BA
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Either.Combinators
import           Data.Function (on)
import           Data.Monoid ((<>))
import qualified Data.Serialize as Serialize
import qualified Data.Text as T
import           Data.Word (Word64, Word8)

import           Jose.Jwa
import           Jose.Types (JwtError(..))
import           Jose.Internal.Parser (IV(..), Tag(..))

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
    RS256 -> go SHA256
    RS384 -> go SHA384
    RS512 -> go SHA512
    _     -> Left . BadAlgorithm . T.pack $ "Not an RSA algorithm: " ++ show a
  where
    go h = either (const $ Left BadCrypto) Right $ PKCS15.sign blinder (Just h) key msg

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
    RS256 -> go SHA256
    RS384 -> go SHA384
    RS512 -> go SHA512
    _     -> False
  where
    go h = PKCS15.verify (Just h) key msg sig

-- | Sign a message using an ECDSA private key.
--
-- The failure condition should only happen if the algorithm is not an ECDSA algorithm in
-- in the JWT standard, or the k value is greater than the group order of the curve
ecSign :: Integer
       -> JwsAlg
       -> ECDSA.PrivateKey
       -> ByteString
       -> Either JwtError ByteString
ecSign k a key msg = case a of
    ES256 -> go SHA256
    ES384 -> go SHA384
    ES512 -> go SHA512
    _     -> Left . BadAlgorithm . T.pack $ "Not a valid JWT ECDSA algorithm: " ++ show a
  where
    go h = maybe (Left BadCrypto) (Right . serSig) $ ECDSA.signWith k key h msg
    serSig = liftA2 ((<>) `on` i2ospOf_ 32) ECDSA.sign_r ECDSA.sign_s

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
    => Enc
    -- ^ The encryption algorithm to be used
    -> m (ScrubbedBytes, ScrubbedBytes)
    -- ^ The key, IV
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
rsaEncrypt :: (MonadRandom m, ByteArray msg, ByteArray out)
    => RSA.PublicKey
    -- ^ The encryption key
    -> JweAlg
    -- ^ The algorithm (@RSA1_5@, @RSA_OAEP@, or @RSA_OAEP_256@)
    -> msg
    -- ^ The message to encrypt
    -> m (Either JwtError out)
    -- ^ The encrypted message
rsaEncrypt k a msg = fmap BA.convert <$> case a of
    RSA1_5       -> mapErr (PKCS15.encrypt k bs)
    RSA_OAEP     -> mapErr (OAEP.encrypt (OAEP.defaultOAEPParams SHA1) k bs)
    RSA_OAEP_256 -> mapErr (OAEP.encrypt (OAEP.defaultOAEPParams SHA256) k bs)
    _            -> return (Left (BadAlgorithm "Not an RSA algorithm"))
  where
    bs = BA.convert msg
    mapErr = fmap (mapLeft (const BadCrypto))

-- | Decrypts an RSA encrypted message.
rsaDecrypt :: ByteArray ct
    => Maybe RSA.Blinder
    -> RSA.PrivateKey
    -- ^ The decryption key
    -> JweAlg
    -- ^ The RSA algorithm to use
    -> ct
    -- ^ The encrypted content
    -> Either JwtError ScrubbedBytes
    -- ^ The decrypted key
rsaDecrypt blinder rsaKey a ct = BA.convert <$> case a of
    RSA1_5       -> mapErr (PKCS15.decrypt blinder rsaKey bs)
    RSA_OAEP     -> mapErr (OAEP.decrypt blinder (OAEP.defaultOAEPParams SHA1) rsaKey bs)
    RSA_OAEP_256 -> mapErr (OAEP.decrypt blinder (OAEP.defaultOAEPParams SHA256) rsaKey bs)
    _            -> Left (BadAlgorithm "Not an RSA algorithm")
  where
    bs = BA.convert ct
    mapErr = mapLeft (const BadCrypto)

-- Dummy type to constrain Cipher type
data C c = C

initCipher :: BlockCipher c => C c -> ScrubbedBytes -> Either JwtError c
initCipher _ k = mapFail (cipherInit k)

-- Map CryptoFailable to JwtError
mapFail :: CryptoFailable a -> Either JwtError a
mapFail (CryptoPassed a) = return a
mapFail (CryptoFailed e) = Left $ case e of
    CryptoError_KeySizeInvalid -> KeyError "cipher key length is invalid"
    _ -> BadCrypto


-- | Decrypt an AES encrypted message.
decryptPayload :: forall ba. (ByteArray ba)
    => Enc
    -- ^ Encryption algorithm
    -> ScrubbedBytes
    -- ^ Content encryption key
    -> IV
    -- ^ IV
    -> ba
    -- ^ Additional authentication data
    -> Tag
    -- ^ The integrity protection value to be checked
    -> ba
    -- ^ The encrypted JWT payload
    -> Maybe ba
decryptPayload enc cek iv_ aad tag_ ct = case (enc, iv_, tag_) of
    (A128GCM, IV12 b, Tag16 t) -> doGCM (C :: C AES128) b t
    (A192GCM, IV12 b, Tag16 t) -> doGCM (C :: C AES192) b t
    (A256GCM, IV12 b, Tag16 t) -> doGCM (C :: C AES256) b t
    (A128CBC_HS256, IV16 b, Tag16 t) -> doCBC (C :: C AES128) b t SHA256 16
    (A192CBC_HS384, IV16 b, Tag24 t) -> doCBC (C :: C AES192) b t SHA384 24
    (A256CBC_HS512, IV16 b, Tag32 t) -> doCBC (C :: C AES256) b t SHA512 32
    _ -> Nothing -- This shouldn't be possible if the JWT was parsed first
  where
    (cbcMacKey, cbcEncKey) = BA.splitAt (BA.length cek `div` 2) cek :: (ScrubbedBytes, ScrubbedBytes)
    al = fromIntegral (BA.length aad) * 8 :: Word64

    doGCM :: BlockCipher c => C c -> ByteString -> ByteString -> Maybe ba
    doGCM c iv tag = do
        cipher <- rightToMaybe (initCipher c cek)
        aead <- maybeCryptoError (aeadInit AEAD_GCM cipher iv)
        aeadSimpleDecrypt aead aad ct (AuthTag $ BA.convert tag)

    doCBC :: (HashAlgorithm a, BlockCipher c) => C c -> ByteString -> ByteString -> a -> Int -> Maybe ba
    doCBC c iv tag a tagLen = do
        checkMac a tag iv tagLen
        cipher <- rightToMaybe (initCipher c cbcEncKey)
        iv'    <- makeIV iv
        unless (BA.length ct `mod` blockSize cipher == 0) Nothing
        unpad $ cbcDecrypt cipher iv' ct

    checkMac :: HashAlgorithm a => a -> ByteString -> ByteString -> Int -> Maybe ()
    checkMac a tag iv l = do
        let mac = BA.take l $ BA.convert $ doMac a iv :: BA.Bytes
        unless (tag `BA.constEq` mac) Nothing

    doMac :: HashAlgorithm a => a -> ByteString -> HMAC a
    doMac _ iv = hmac cbcMacKey (BA.concat [BA.convert aad, iv, BA.convert ct, Serialize.encode al] :: ByteString)

-- | Encrypt a message using AES.
encryptPayload :: forall ba iv. (ByteArray ba, ByteArray iv)
    => Enc
    -- ^ Encryption algorithm
    -> ScrubbedBytes
    -- ^ Content management key
    -> iv
    -- ^ IV
    -> ba
    -- ^ Additional authenticated data
    -> ba
    -- ^ The message/JWT claims
    -> Maybe (AuthTag, ba)
    -- ^ Ciphertext claims and signature tag
encryptPayload e cek iv aad msg = case e of
    A128GCM       -> doGCM (C :: C AES128)
    A192GCM       -> doGCM (C :: C AES192)
    A256GCM       -> doGCM (C :: C AES256)
    A128CBC_HS256 -> doCBC (C :: C AES128) SHA256 16
    A192CBC_HS384 -> doCBC (C :: C AES192) SHA384 24
    A256CBC_HS512 -> doCBC (C :: C AES256) SHA512 32
  where
    (cbcMacKey, cbcEncKey) = BA.splitAt (BA.length cek `div` 2) cek :: (ScrubbedBytes, ScrubbedBytes)
    al = fromIntegral (BA.length aad) * 8 :: Word64

    doGCM c = do
        cipher <- rightToMaybe (initCipher c cek)
        aead <- maybeCryptoError (aeadInit AEAD_GCM cipher iv)
        return $ aeadSimpleEncrypt aead aad msg 16

    doCBC :: (HashAlgorithm a, BlockCipher c) => C c -> a -> Int -> Maybe (AuthTag, ba)
    doCBC c a tagLen = do
        cipher <- rightToMaybe (initCipher c cbcEncKey)
        iv'    <- makeIV iv
        let ct = cbcEncrypt cipher iv' (pad msg)
            mac = doMac a ct
            tag = BA.take tagLen (BA.convert mac)
        return (AuthTag tag, ct)

    doMac :: HashAlgorithm a => a -> ba -> HMAC a
    doMac _ ct = hmac cbcMacKey (BA.concat [BA.convert aad, BA.convert iv, BA.convert ct, Serialize.encode al] :: ByteString)

unpad :: (ByteArray ba) => ba -> Maybe ba
unpad bs
    | padLen > 16 || padLen /= BA.length padding = Nothing
    | BA.any (/= padByte) padding = Nothing
    | otherwise = return pt
  where
    len     = BA.length bs
    padByte = BA.index bs (len-1)
    padLen  = fromIntegral padByte
    (pt, padding) = BA.splitAt (len - padLen) bs

pad ::  (ByteArray ba) => ba -> ba
pad bs = BA.append bs padding
  where
    lastBlockSize = BA.length bs `mod` 16
    padByte       = fromIntegral $ 16 - lastBlockSize :: Word8
    padding       = BA.replicate (fromIntegral padByte) padByte


-- Key wrapping and unwrapping functions

-- | <https://tools.ietf.org/html/rfc3394#section-2.2.1>
keyWrap :: ByteArray ba => JweAlg -> ScrubbedBytes -> ScrubbedBytes -> Either JwtError ba
keyWrap alg kek cek = case alg of
    A128KW -> doKeyWrap (C :: C AES128)
    A192KW -> doKeyWrap (C :: C AES192)
    A256KW -> doKeyWrap (C :: C AES256)
    _      -> Left (BadAlgorithm "Not a keywrap algorithm")
  where
    l = BA.length cek
    n = l `div` 8
    iv = BA.replicate 8 166 :: ByteString

    doKeyWrap c = do
        when (l < 16 || l `mod` 8 /= 0) (Left (KeyError "Invalid content key"))
        cipher <- initCipher c kek
        let p = toBlocks cek
            (r0, r) = foldl (doRound (ecbEncrypt cipher) 1) (BA.convert iv, p) [0..5]
        Right $ BA.concat (r0 : r)

    doRound _ _  (a, []) _ = (a, [])
    doRound enc i (a, r:rs) j =
        let b  = enc $ BA.concat [a, r]
            t  = fromIntegral ((n*j) + i) :: Word8
            a' = txor t (BA.take 8 b)
            r' = BA.drop 8 b
            next = doRound enc (i+1) (a', rs) j
        in (fst next, r' : snd next)

txor :: ByteArray ba => Word8 -> ba -> ba
txor t b =
    let n = BA.length b
        lastByte = BA.index b (n-1)
        initBytes = BA.take (n-1) b
      in BA.snoc initBytes (lastByte `xor` t)

toBlocks :: ByteArray ba => ba -> [ba]
toBlocks bytes
    | BA.null bytes = []
    | otherwise = let (b, bs') = BA.splitAt 8 bytes
                   in b : toBlocks bs'

keyUnwrap :: ByteArray ba => ScrubbedBytes -> JweAlg -> ba -> Either JwtError ScrubbedBytes
keyUnwrap kek alg encK = case alg of
    A128KW -> doUnWrap (C :: C AES128)
    A192KW -> doUnWrap (C :: C AES192)
    A256KW -> doUnWrap (C :: C AES256)
    _      -> Left (BadAlgorithm "Not a keywrap algorithm")
  where
    l = BA.length encK
    n = (l `div` 8) - 1
    iv = BA.replicate 8 166

    doUnWrap c = do
        when (l < 24 || l `mod` 8 /= 0) (Left BadCrypto)
        cipher <- initCipher c kek
        let r = toBlocks encK
            (p0, p) = foldl (doRound (ecbDecrypt cipher) n) (head r, reverse (tail r)) (reverse [0..5])
        unless (p0 == iv) (Left BadCrypto)
        Right $ BA.concat (reverse p)

    doRound _ _  (a, []) _ = (a, [])
    doRound dec i (a, r:rs) j =
        let b  = dec $ BA.concat [txor t a, r]
            t  = fromIntegral ((n*j) + i) :: Word8
            a' = BA.take 8 b
            r' = BA.drop 8 b
            next = doRound dec (i-1) (a', rs) j
        in (fst next, r' : snd next)
