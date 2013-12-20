{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE RecordWildCards #-}
module Pontarius.E2E
       ( -- * End-user API
         newSession
       , DSAKeyPair
       , E2EContext
       , E2EGlobals(..)
       , E2EMessage(..)
       , E2EParameters(..)
       , E2ESession
       , Fingerprint
       , KeyType(..)
       , MsgState(..)
       , e2eDefaultParameters
         -- * Development helpers
       , takeAkeMessage
       , takeDataMessage
       , alice
       , bob
       , pubkeyFingerprint
       )

       where

import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Hash.SHA256 as SHA256 (hash)
import qualified Crypto.MAC.HMAC as HMAC
import qualified Data.ByteString as BS
import           Pontarius.E2E.AKE
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Session
import           Pontarius.E2E.Types

e2eDefaultPrime :: Integer
e2eDefaultPrime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF



e2eDefaultCtrEncryption :: BS.ByteString
                        -> BS.ByteString
                        -> BS.ByteString
                        -> BS.ByteString
e2eDefaultCtrEncryption iv k x = AES.encryptCTR key iv x
  where
    key = AES.initAES k


e2eDefaultCheckMac :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Bool
e2eDefaultCheckMac key pl mc = HMAC.hmac SHA256.hash (512 `div` 8) key pl =~= mc

e2eDefaultParameters :: E2EParameters
e2eDefaultParameters = E2EParameters { paramDHPrime = e2eDefaultPrime
                                     , paramDHGenerator = 2
                                     , paramDHKeySizeBits = 320
                                     , paramEncrypt = e2eDefaultCtrEncryption
                                     , paramEncryptionBlockSize = 128 -- check bits / bytes
                                     , paramEncryptionKeySize = 128
                                     , paramHash = SHA256.hash
                                     , paramMac = HMAC.hmac SHA256.hash (512 `div` 8)
                                     , paramCheckMac = e2eDefaultCheckMac
                                     , sendPubkey = False
                                     }
