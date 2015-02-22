{-# LANGUAGE OverloadedStrings #-}
module Main where

import Criterion.Main
import Crypto.Random
import Jose.Jws
import Jose.Jwa
import Jose.Jwt
import Keys

main = do
    rng <- cprgCreate `fmap` createEntropyPool :: IO SystemRNG
    let msg = "The best laid schemes o' mice and men"
        rsaE a m  = case fst $ rsaEncode rng a jwsRsaPrivateKey m of
            Left  _       -> error "RSA encode shouldn't fail"
            Right (Jwt j) -> j
        hmacE a m = case hmacEncode a jwsHmacKey m of
            Left _        -> error "HMAC shouldn't fail"
            Right (Jwt j) -> j

    defaultMain
      [ bgroup "JWS"
          [ bench "encode RSA256" $ nf (rsaE RS256)  msg
          , bench "encode RSA384" $ nf (rsaE RS384)  msg
          , bench "encode RSA512" $ nf (rsaE RS384)  msg
          , bench "encode HS256"  $ nf (hmacE HS256) msg
          , bench "encode HS512"  $ nf (hmacE HS512) msg
          ]
      ]
