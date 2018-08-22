{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_HADDOCK prune #-}

-- | Parses encoded JWTs into data structures which can be handled

module Jose.Internal.Parser
    ( parseJwt
    , DecodableJwt (..)
    , EncryptedCEK (..)
    , Payload (..)
    , IV (..)
    , Tag (..)
    , AAD (..)
    , Sig (..)
    , SigTarget (..)
    )
where

import Data.Aeson (eitherDecodeStrict')
import           Data.Attoparsec.ByteString (Parser)
import qualified Data.Attoparsec.ByteString as P
import qualified Data.Attoparsec.ByteString.Char8 as PC
import           Data.ByteArray.Encoding (convertFromBase, Base(..))
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Either.Combinators (mapLeft)

import           Jose.Jwa
import           Jose.Types (JwtError(..), JwtHeader(..), JwsHeader(..), JweHeader(..))


data DecodableJwt
     = Unsecured ByteString
     | DecodableJws JwsHeader Payload Sig SigTarget
     | DecodableJwe JweHeader EncryptedCEK IV Payload Tag AAD


data Tag
    = Tag16 ByteString
    | Tag24 ByteString
    | Tag32 ByteString


data IV
    = IV12 ByteString
    | IV16 ByteString


newtype Sig = Sig ByteString
newtype SigTarget = SigTarget ByteString
newtype AAD = AAD ByteString
newtype Payload = Payload ByteString
newtype EncryptedCEK = EncryptedCEK ByteString


parseJwt :: ByteString -> Either JwtError DecodableJwt
parseJwt bs = mapLeft (const BadCrypto) $ P.parseOnly jwt bs


jwt :: Parser DecodableJwt
jwt = do
    (hdr, raw) <- jwtHeader
    case hdr of
        UnsecuredH -> Unsecured <$> base64Chunk
        JwsH h -> do
            payloadB64 <- PC.takeWhile ('.' /=) <* PC.char '.'
            payload <- b64Decode payloadB64
            s <- sig (jwsAlg h)
            pure $ DecodableJws h (Payload payload) s (SigTarget (B.concat [raw, ".", payloadB64]))
        JweH h ->
            DecodableJwe
                <$> pure h
                <*> encryptedCEK
                <*> iv (jweEnc h)
                <*> encryptedPayload
                <*> authTag (jweEnc h)
                <*> pure (AAD raw)


sig :: JwsAlg -> Parser Sig
sig _ = do
    t <- P.takeByteString >>= b64Decode
    pure (Sig t)


authTag :: Enc -> Parser Tag
authTag e = do
    t <- P.takeByteString >>= b64Decode
    case e of
        A128GCM -> tag16 t
        A192GCM -> tag16 t
        A256GCM -> tag16 t
        A128CBC_HS256 -> tag16 t
        A192CBC_HS384 -> tag24 t
        A256CBC_HS512 -> tag32 t
  where
    badTag = "invalid auth tag"
    tag16 t = if B.length t /= 16 then fail badTag else pure (Tag16 t)
    tag24 t = if B.length t /= 24 then fail badTag else pure (Tag24 t)
    tag32 t = if B.length t /= 32 then fail badTag else pure (Tag32 t)


iv :: Enc -> Parser IV
iv e = do
    bs <- base64Chunk
    case e of
        A128GCM -> iv12 bs
        A192GCM -> iv12 bs
        A256GCM -> iv12 bs
        _ -> iv16 bs
  where
    iv12 bs = if B.length bs /= 12 then fail "invalid iv" else pure (IV12 bs)
    iv16 bs = if B.length bs /= 16 then fail "invalid iv" else pure (IV16 bs)


encryptedCEK :: Parser EncryptedCEK
encryptedCEK = EncryptedCEK <$> base64Chunk


encryptedPayload :: Parser Payload
encryptedPayload = Payload <$> base64Chunk


jwtHeader :: P.Parser (JwtHeader, ByteString)
jwtHeader = do
    hdrB64 <- PC.takeWhile ('.' /=) <* PC.char '.'
    hdrBytes <- b64Decode hdrB64 :: P.Parser ByteString
    hdr <- parseHdr hdrBytes
    return (hdr, hdrB64)
  where
    parseHdr bs = either fail return (eitherDecodeStrict' bs)


base64Chunk :: P.Parser ByteString
base64Chunk = do
    bs <- PC.takeWhile ('.' /=) <* PC.char '.'
    b64Decode bs


b64Decode :: ByteString -> P.Parser ByteString
b64Decode bs = either (const (fail "Invalid Base64")) return $ convertFromBase Base64URLUnpadded bs
