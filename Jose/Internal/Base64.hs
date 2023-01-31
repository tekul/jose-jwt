{-# LANGUAGE OverloadedStrings, FlexibleContexts, CPP #-}
{-# OPTIONS_HADDOCK hide #-}

-- | JWT-style base64 encoding and decoding

module Jose.Internal.Base64 where

#if MIN_VERSION_mtl(2,2,1)
import Control.Monad.Except
#else
import Control.Monad.Error
#endif

import Data.ByteArray
import Data.ByteArray.Encoding

import Jose.Types

-- | Base64 URL encode without padding.
encode :: (ByteArrayAccess input, ByteArray output) => input -> output
encode = convertToBase Base64URLUnpadded

-- | Base64 decode.
decode :: (ByteArrayAccess input, ByteArray output, MonadError JwtError m) => input -> m output
decode bs = either (throwError . Base64Error) return $ convertFromBase Base64URLUnpadded bs
