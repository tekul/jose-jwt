module Main where

import Test.Hspec (hspec)

import Tests.JwsSpec
import Tests.JweSpec
import Tests.JwkSpec

main :: IO ()
main = hspec $ do
    Tests.JwsSpec.spec
    Tests.JweSpec.spec
    Tests.JwkSpec.spec
