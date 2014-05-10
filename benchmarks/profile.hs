{-# LANGUAGE BangPatterns, OverloadedStrings #-}
module Main where

import Crypto.Random
import Data.Jwt
import qualified Data.ByteString.Char8 as B
import Keys

msgPrefix = "The best laid schemes o' mice and men..."

main = do
    --rng <- cprgCreate `fmap` createEntropyPool :: IO SystemRNG
    let !msgs = map ((B.append msgPrefix) . B.pack . show) [1..10000]

    mapM_ B.putStrLn $ map (jwsHmacEncode HS512 jwsHmacKey) msgs
