{-# LANGUAGE OverloadedStrings #-}

module Jose.Jwt
    ( module Jose.Types
    , header
    )
where

import Data.ByteString (ByteString)
import Jose.Types

{-| Returns the JWT header, allowing the details to be inspected
 - before decoding. Useful when you need to support multiple
 - encoding strategies and don't know in advance how a
 - particular JWT will be encoded.
 -}

header :: ByteString -> Either JwtError JwtHeader
header = undefined



