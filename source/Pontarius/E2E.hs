{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE RecordWildCards #-}
module Pontarius.E2E where

import Control.Concurrent

import           Pontarius.E2E.Monad
import           Pontarius.E2E.Serialize
import           Pontarius.E2E.Types
import           Pontarius.E2E.Helpers


-- keyDerivs :: Integer -> KeyDerivatives


newState = do
    opk <- makeDHKeyPair
    ock <- makeDHKeyPair
    ndh <- makeDHKeyPair
    -- instance Tag has to be >= 0x100
    return E2EState{ ourPreviousKey   = opk
                   , ourCurrentKey    = ock
                   , ourKeyID         = 1
                   , theirPublicKey   = Nothing
                   , theirCurrentKey  = Nothing
                   , mostRecentKey    = 2
                   , nextDH           = ndh
                   , theirPreviousKey = Nothing
                   , theirKeyID       = 0
                   , authState        = AuthStateNone
                   , msgState         = MsgStatePlaintext
                   , counter          = 1
                   , ssid             = Nothing
                   , verified         = False
                   , smpState         = Nothing
                   }
