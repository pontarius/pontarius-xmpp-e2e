{-# LANGUAGE NamedFieldPuns #-}
module Pontarius.E2E.Message where

import           Control.Monad
import           Control.Monad.Except
import           Control.Monad.State.Strict
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import           Data.Word (Word8)

import           Pontarius.E2E.Monad
import           Pontarius.E2E.Types
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Serialize

decryptDataMessage :: CRandom.CPRG g => DataMessage -> E2E g BS.ByteString
decryptDataMessage msg = do
    s <- get
    unless (isEncrypted $ msgState s) . throwError
          $ WrongState "decryptDataMessage"
    MK{ recvEncKey
      , recvMacKey } <- makeMessageKeys (senderKeyID msg) (recipientKeyID msg)
    check <- parameter paramCheckMac
    protocolGuard MACFailure "message" $ check recvMacKey (encodeMessageBytes msg)
                                                          (messageMAC msg)
    case () of () | recipientKeyID msg == ourKeyID s     -> return ()
                  | recipientKeyID msg == ourKeyID s + 1 -> shiftKeys
                  | otherwise -> throwError $ ProtocolError WrongKeyID ""
    pl <- decCtr recvEncKey (ctrHi msg) (messageEnc msg)
    shiftTheirKeys (nextDHy msg) (senderKeyID msg)
    return pl
  where
    isEncrypted MsgStateEncrypted{} = True
    isEncrypted _ = False
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

makeMessageKeys :: Integer
                -> Integer
                -> E2E g MessageKeys
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

encryptDataMessage :: BS.ByteString -> E2E g DataMessage
encryptDataMessage payload = do
    s <- get
    unless (isEncrypted $ msgState s) $ throwError (WrongState "encryptDataMessage")
    mk <- makeMessageKeys (theirKeyID s) (ourKeyID s)
    pl <- encCtr (sendEncKey mk) (encodeInteger $ counter s) payload
    let msg = DM { senderKeyID = ourKeyID s
                 , recipientKeyID = theirKeyID s
                 , nextDHy = pub $ nextDH s
                 , ctrHi  = encodeInteger $ counter s
                 , messageEnc = pl
                 , messageMAC = BS.empty
                 }
    messageMAC <- mac (sendMacKey mk) (encodeMessageBytes msg)
    put s{counter = counter s + 1}
    return $ msg{messageMAC = messageMAC}
  where
    isEncrypted MsgStateEncrypted{} = True
    isEncrypted _ = False
