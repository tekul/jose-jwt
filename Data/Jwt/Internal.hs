{-# LANGUAGE OverloadedStrings #-}

module Data.Jwt.Internal where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base64.URL as B64

import Data.Jwt.Types

b64Encode :: ByteString -> ByteString
b64Encode = strip . B64.encode
  where
    strip "" = ""
    strip bs = case BC.last bs of
      '=' -> strip $ B.init bs
      _   -> bs

b64Decode :: ByteString -> Either JwtError ByteString
b64Decode bs = either (Left . Base64Error) Right $ B64.decode bsPadded
  where
    bsPadded = case B.length bs `mod` 4 of
      3 -> bs `BC.snoc` '='
      2 -> bs `B.append` "=="
      _ -> bs

