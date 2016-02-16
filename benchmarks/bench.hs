{-# LANGUAGE OverloadedStrings, CPP #-}
module Main where

import Criterion.Main
import Crypto.Random
import Data.Word (Word64)
import Jose.Jws
import Jose.Jwa
import Jose.Jwt
import Keys

benchRNG = drgNewTest (w, w, w, w, w) where w = 1 :: Word64

fstWithRNG = fst . withDRG benchRNG

main = do
    let msg = "The best laid schemes o' mice and men"
        rsaE a m  = case fstWithRNG (rsaEncode a jwsRsaPrivateKey m) of
            Left  _       -> error "RSA encode shouldn't fail"
            Right (Jwt j) -> j
        hmacE a m = case hmacEncode a jwsHmacKey m of
            Left _        -> error "HMAC shouldn't fail"
            Right (Jwt j) -> j

    defaultMain
      [ bgroup "JWS"
          [ bench "encode RSA256" $ nf (rsaE RS256)  msg
#if MIN_VERSION_cryptonite(0,13,0)
          , bench "encode RSA384" $ nf (rsaE RS384)  msg
#endif
          , bench "encode RSA512" $ nf (rsaE RS512)  msg
          , bench "encode HS256"  $ nf (hmacE HS256) msg
          , bench "encode HS384"  $ nf (hmacE HS384) msg
          , bench "encode HS512"  $ nf (hmacE HS512) msg
          ]
      ]
