{-# LANGUAGE NamedFieldPuns #-}
module Pontarius.E2E.Message where

import           Control.Applicative ((<$>), (<*>), pure)
import           Control.Concurrent.MVar
import qualified Control.Exception as Ex
import           Control.Monad
import           Control.Monad.Error
import           Control.Monad.Reader
import           Control.Monad.State.Strict
import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Hash.SHA1 as SHA1 (hash)
import qualified Crypto.Hash.SHA256 as SHA256 (hash)
import qualified Crypto.MAC.HMAC as HMAC
import           Crypto.Number.ModArithmetic as Mod
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Random as CRandom
import           Data.Bits hiding (shift)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import           Data.Byteable (constEqBytes)
import qualified Data.Serialize as Serialize
import           Data.Word (Word8)
import           Numeric
import qualified System.IO.Unsafe as Unsafe

import           Pontarius.E2E.Monad
import           Pontarius.E2E.Types
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Serialize

encodeMessageBytes :: DataMessage -> BS.ByteString
encodeMessageBytes DM{} = BS.empty -- TODO

decryptDataMessage :: CRandom.CPRG g => DataMessage -> E2E g BS.ByteString
decryptDataMessage msg = do
    s <- get
    unless (msgState s == MsgStateEncrypted) $ throwError WrongState
    MK{ recvEncKey
      , recvMacKey } <- makeMessageKeys (senderKeyID msg) (recipientKeyID msg)
    check <- parameter paramCheckMac
    protocolGuard MACFailure "message" $ check recvMacKey (encodeMessageBytes msg)
                                                          (messageMAC msg)
    case () of () | recipientKeyID msg == ourKeyID s     -> return ()
                  | recipientKeyID msg == ourKeyID s + 1 -> shiftKeys
                  | otherwise -> throwError $ ProtocolError WrongKeyID ""
    pl <- decCtr (ctrHi msg) recvEncKey (messageEnc msg)
    shiftTheirKeys (nextDHy msg) (senderKeyID msg)
    return pl
  where
    shiftKeys = do
        newDH <- makeDHKeyPair
        s <- get
        put s{ ourPreviousKey = ourCurrentKey s
             , ourCurrentKey = nextDH s
             , nextDH = newDH
             , ourKeyID = ourKeyID s + 1
             }
    shiftTheirKeys newKey keyID = do
        s <- get
        when (keyID == theirKeyID s) $
            put s{ theirPreviousKey = theirCurrentKey s
                 , theirCurrentKey = Just newKey
                 , theirKeyID = theirKeyID s + 1
                 }

makeMessageKeys tKeyID oKeyID = do
    s <- get
    tck <- case ( tKeyID == theirKeyID s - 1
                , tKeyID == theirKeyID s
                , theirPreviousKey s
                , theirCurrentKey s
                ) of
               (True, _   , Just tpk , _        ) -> return tpk
               (True, _   , Nothing  , _        ) -> throwError NoPeerDHKey
               (_   , True, _        , Just tck ) -> return tck
               (_   , True, _        , Nothing  ) -> throwError NoPeerDHKey
               _                              -> throwError
                                                 $ ProtocolError WrongKeyID ""
    ok <- case ( oKeyID == ourKeyID s
               , oKeyID == ourKeyID s + 1
               ) of
               (True, _) -> return $ ourCurrentKey s
               (_, True) -> return $ nextDH s
               _ -> throwError $ ProtocolError WrongKeyID ""
    sharedSecret <- makeDHSharedSecret (priv ok) tck
    let secBytes = encodeInteger sharedSecret
        (sendByte, recvByte) = if tck <= pub ok
                               then (0x01, 0x02) :: (Word8, Word8)
                               else (0x02, 0x01)
    let h1 b = hash (BS.singleton b `BS.append` secBytes)
    -- TODO: Check against yabasta
    sendEncKey <- h1 sendByte
    sendMacKey <- hash sendEncKey
    recvEncKey <- h1 recvByte
    recvMacKey <- hash recvEncKey
    return MK{ sendEncKey
             , sendMacKey
             , recvEncKey
             , recvMacKey
             }
