{-# LANGUAGE OverloadedStrings, FlexibleContexts #-}
{-# OPTIONS_HADDOCK prune #-}

module Jose.Jwt
    ( module Jose.Types
    , decode
    , decodeClaims
    )
where

import Control.Error
import Control.Monad.State.Strict
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.PubKey.RSA (PrivateKey(..))
import Crypto.Random (CPRG)
import Data.Aeson (decodeStrict')
import Data.ByteString (ByteString)
import Data.List (find)
import Data.Maybe (fromJust)
import qualified Data.ByteString.Char8 as BC

import qualified Jose.Internal.Base64 as B64
import Jose.Types
import Jose.Jwk

import qualified Jose.Jws as Jws
import qualified Jose.Jwe as Jwe


-- | Uses the supplied keys to decode a JWT.
-- Locates a matching key by header @kid@ value where possible
-- or by suitable key type.
-- The JWK @use@ and @alg@ options are currently ignored.
decode :: CPRG g
       => g
       -> [Jwk]                    -- ^ The keys to use for decoding
       -> ByteString               -- ^ The encoded JWT
       -> (Either JwtError Jwt, g) -- ^ The decoded JWT, if successful
decode rng keySet jwt = flip runState rng $ runEitherT $ do
    let components = BC.split '.' jwt
    when (length components < 3) $ left $ BadDots 2
    hdr <- B64.decode (head components) >>= hoistEither . parseHeader
    ks  <- findKeys hdr keySet
    -- Now we have one or more suitable keys.
    -- Try each in turn until successful
    let decodeWith = case hdr of
                       JwsH _ -> decodeWithJws
                       _      -> decodeWithJwe
    decodings <- mapM decodeWith ks
    maybe (left $ KeyError "None of the keys was able to decode the JWT") (return . fromJust) $ find isJust decodings
  where
    decodeWithJws :: CPRG g => Jwk -> EitherT JwtError (State g) (Maybe Jwt)
    decodeWithJws k = either (const $ return Nothing) (return . Just . Jws) $ case k of
        RsaPublicJwk  kPub _ _ _ -> Jws.rsaDecode kPub jwt
        RsaPrivateJwk kPr  _ _ _ -> Jws.rsaDecode (private_pub kPr) jwt
        EcPublicJwk   kPub _ _ _ -> Jws.ecDecode kPub jwt
        EcPrivateJwk  kPr  _ _ _ -> Jws.ecDecode (ECDSA.toPublicKey kPr) jwt
        SymmetricJwk  kb   _ _ _ -> Jws.hmacDecode kb jwt

    decodeWithJwe :: CPRG g => Jwk -> EitherT JwtError (State g) (Maybe Jwt)
    decodeWithJwe k = case k of
        RsaPrivateJwk kPr _ _ _ -> do
            g <- lift get
            let (e, g') = Jwe.rsaDecode g kPr jwt
            lift $ put g'
            either (const $ return Nothing) (return . Just . Jwe) e
        _                       -> left $ KeyError "Not a JWE key (shouldn't happen)"

-- | Convenience function to return the claims contained in a JWT.
-- This is required in situations such as client assertion authentication,
-- where the contents of the JWT may be required in order to work out
-- which key should be used to verify the token.
-- Obviously this should not be used by itself to decode a token since
-- no integrity checking is done and the contents may be forged.
decodeClaims :: ByteString
             -> Either JwtError (JwtHeader, JwtClaims)
decodeClaims jwt = do
    let components = BC.split '.' jwt
    when (length components /= 3) $ Left $ BadDots 2
    hdr    <- B64.decode (head components) >>= parseHeader
    claims <- B64.decode ((head . tail) components) >>= parseClaims
    return (hdr, claims)
  where
    parseClaims bs = maybe (Left BadClaims) Right $ decodeStrict' bs


findKeys :: Monad m => JwtHeader -> [Jwk] -> EitherT JwtError m [Jwk]
findKeys hdr jwks = checkKeys $ case hdr of
    JweH h -> findMatchingJweKeys jwks h
    JwsH h -> findMatchingJwsKeys jwks h
  where
    -- TODO Move checks to JWK and support better error messages
    checkKeys [] = left $ KeyError "No suitable key was found to decode the JWT"
    checkKeys ks = return ks

