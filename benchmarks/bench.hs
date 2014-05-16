{-# LANGUAGE OverloadedStrings #-}
module Main where

import Criterion.Main
import Crypto.Random
import Jose.Jws
import Jose.Jwa
import Keys

main = do
    rng <- cprgCreate `fmap` createEntropyPool :: IO SystemRNG
    let msg = "The best laid schemes o' mice and men"

    defaultMain
      [ bgroup "JWS"
          [ bench "encode RSA256" $ nf (rsaEncode RS256 jwsRsaPrivateKey) msg
          , bench "encode RSA384" $ nf (rsaEncode RS384 jwsRsaPrivateKey) msg
          , bench "encode RSA512" $ nf (rsaEncode RS384 jwsRsaPrivateKey) msg
          , bench "encode HS256"  $ nf (hmacEncode HS256 jwsHmacKey) msg
          , bench "encode HS512"  $ nf (hmacEncode HS512 jwsHmacKey) msg
          ]
      ]
