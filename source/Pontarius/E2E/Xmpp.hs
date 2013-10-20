{-# LANGUAGE ScopedTypeVariables #-}
module Pontarius.E2E.Xmpp  where

import           Control.Applicative ((<$>))
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import           Data.XML.Pickle
import           Network.Xmpp
import           Pontarius.E2E
import           Pontarius.E2E.Serialize
import           Pontarius.E2E.Session
import           Pontarius.E2E.Types

-- PEM
import qualified Crypto.Types.PubKey.DSA as DSA
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types hiding (Set)
import qualified Data.ByteString.Lazy as BSL
import           Data.PEM

data E2EContext = E2ECtx { e2eSess :: E2ESession CRandom.SystemRNG
                         , peer :: Jid
                         }

sendE2eMessage xmppSession to msg  = do
    let xml = pickle (xpRoot . xpUnliftElems $ e2eMessageXml) msg
    case msg of
        E2EDataMessage{} -> sendMessage message{ messageTo = Just to
                                               , messagePayload = [xml]
                                               }
                                        xmppSession
        E2EAkeMessage{} -> iqSendHelper xml
        E2EEndSessionMessage -> iqSendHelper xml
    return ()
  where
    iqSendHelper pl = do
        res <- sendIQ' (Just to) Set Nothing pl xmppSession
        case res of
            Just IQResponseResult{} -> return True
            _ -> return False

data Side = Initiator | Responder deriving (Show, Eq)

newContext :: DSAKeyPair
           -> Jid
           -> Side
           -> (Maybe BS.ByteString -> IO BS.ByteString)
           -> (MsgState -> IO ())
           -> (Bool -> IO ())
           -> Session
           -> IO E2EContext
newContext dsaKey to side mkSecret oss onAuthChange xmppSession = do
    sess <- newSession (E2EG e2eDefaultParameters dsaKey) mkSecret oss onAuthChange (sendE2eMessage xmppSession to)
    _ <- startAke sess (case side of Initiator -> alice; Responder -> bob)
    return $ E2ECtx sess to

recvMessage :: Message
            -> E2EContext
            -> IO (Maybe (Either E2EError [BS.ByteString]))
recvMessage msg ctx = do
    if messageFrom msg /= Just (peer ctx)
        then return Nothing
        else case unpickle (xpClean . xpUnliftElems $ e2eMessageXml)
                           $ messagePayload msg of
                 Left _ -> return Nothing
                 Right msg' -> Just <$> takeMessage (e2eSess ctx) msg'

recvIQ iq ctx = do
    if iqRequestFrom iq /= Just (peer ctx)
        then return Nothing
        else case unpickle (xpRoot . xpUnliftElems $ e2eMessageXml)
                           $ iqRequestPayload iq of
                 Left _ -> return Nothing
                 Right msg' -> Just <$> takeMessage (e2eSess ctx) msg'


sendMsg :: BS.ByteString -> E2EContext -> IO (Either E2EError ())
sendMsg msg ctx = sendDataMessage msg (e2eSess ctx)

getKey :: FilePath -> IO (DSA.PublicKey, DSA.PrivateKey)
getKey keyFile = do
    Right ((PEM pName _ bs) : _) <- pemParseLBS `fmap` (BSL.readFile keyFile)
    let Right keysASN1 = decodeASN1 DER (BSL.fromChunks [bs])
    let Right (keyPair ::DSA.KeyPair,  _) = fromASN1 keysASN1
    return (DSA.toPublicKey keyPair, DSA.toPrivateKey keyPair)
