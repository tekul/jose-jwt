{-# LANGUAGE OverloadedStrings #-}
module Main where

import Criterion.Main
import Crypto.Random
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import Data.Word (Word64)
import Jose.Jws
import qualified Jose.Jwe as Jwe
import Jose.Jwa
import Jose.Jwt
import Jose.Jwk
import Keys

benchRNG = drgNewTest (w, w, w, w, w) where w = 1 :: Word64

fstWithRNG = fst . withDRG benchRNG

msg = "The best laid schemes o' mice and men"

main = do
    kwKek <- getRandomBytes 32 >>= \k -> return $ SymmetricJwk k Nothing Nothing Nothing :: IO Jwk
    ed25519PrivKey <- Ed25519.generateSecretKey
    ed448PrivKey <- Ed448.generateSecretKey
    let ed25519PubKey = Ed25519.toPublic ed25519PrivKey
        ed448PubKey = Ed448.toPublic ed448PrivKey
    Right rsaOAEPJwe <- Jwe.rsaEncode RSA_OAEP A256GCM jwsRsaPublicKey msg
    Right keywrapJwe <- Jwe.jwkEncode A256KW A256GCM kwKek (Claims msg)

    defaultMain
      [ benchJwsHmac
      , benchJwsRsa
      , benchJwsEd25519 ed25519PrivKey ed25519PubKey
      , benchJwsEd448 ed448PrivKey ed448PubKey
      , benchJweKeywrap (unJwt keywrapJwe) kwKek
      , benchJweRsa (unJwt rsaOAEPJwe)
      ]


benchJweRsa jwe = bgroup "JWE-RSA"
    [ bench "decode RSA_OAEP" $ nf rsaDecrypt jwe
    ]
  where
     rsaDecrypt m = case fstWithRNG (Jwe.rsaDecode jwsRsaPrivateKey m) of
        Left _ -> error "RSA decode of JWE shouldn't fail"
        Right j -> snd j

benchJweKeywrap jwe jwk = bgroup "JWE-KW"
    [ bench "decode A256KW" $ nf keywrapDecode jwe
    ]
  where
     keywrapDecode m = case fstWithRNG (Jwe.jwkDecode jwk m) of
        Right (Jwe j) -> snd j
        _ -> error "RSA decode of JWE shouldn't fail"


benchJwsEd25519 kPr kPub = bgroup "Ed25519"
    [ bench "encode Ed25519" $ nf (unJwt . ed25519Encode kPr kPub) msg
    ]

benchJwsEd448 kPr kPub = bgroup "Ed448"
    [ bench "encode Ed448" $ nf (unJwt . ed448Encode kPr kPub) msg
    ]

benchJwsRsa = bgroup "JWS-RSA"
    [ bench "encode RSA256" $ nf (rsaE RS256)  msg
    , bench "encode RSA384" $ nf (rsaE RS384)  msg
    , bench "encode RSA512" $ nf (rsaE RS512)  msg
    ]
  where
    rsaE a m  = case fstWithRNG (rsaEncode a jwsRsaPrivateKey m) of
        Left  _       -> error "RSA encode shouldn't fail"
        Right (Jwt j) -> j

benchJwsHmac = bgroup "JWS-HMAC"
    [ bench "encode HS256"  $ nf (hmacE HS256) msg
    , bench "encode HS384"  $ nf (hmacE HS384) msg
    , bench "encode HS512"  $ nf (hmacE HS512) msg
    ]
  where
    hmacE a m = case hmacEncode a jwsHmacKey m of
        Left _        -> error "HMAC shouldn't fail"
        Right (Jwt j) -> j
