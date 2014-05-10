{-# LANGUAGE BangPatterns, OverloadedStrings #-}
module Main where

import Criterion.Main
import Crypto.Random
import Data.Jwt
import Keys

main = do
    rng <- cprgCreate `fmap` createEntropyPool :: IO SystemRNG
    let !msg = "The best laid schemes o' mice and men"

    defaultMain
      [ bgroup "JWS"
          [ bench "encode RSA256" $ nf (jwsRsaEncode RS256 jwsRsaPrivateKey) msg
          , bench "encode RSA384" $ nf (jwsRsaEncode RS384 jwsRsaPrivateKey) msg
          , bench "encode RSA512" $ nf (jwsRsaEncode RS384 jwsRsaPrivateKey) msg
          , bench "encode HS256"  $ nf (jwsHmacEncode HS256 jwsHmacKey) msg
          , bench "encode HS512"  $ nf (jwsHmacEncode HS512 jwsHmacKey) msg
          ]
      ]
