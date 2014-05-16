{-# LANGUAGE BangPatterns, OverloadedStrings #-}
module Main where

import Crypto.Random
import Jose.Jws
import Jose.Jwa
import qualified Data.ByteString.Char8 as B
import Keys

msgPrefix = "The best laid schemes o' mice and men..."

main = do
    --rng <- cprgCreate `fmap` createEntropyPool :: IO SystemRNG
    let !msgs = map ((B.append msgPrefix) . B.pack . show) [1..10000]

    mapM_ B.putStrLn $ map (hmacEncode HS512 jwsHmacKey) msgs
