{-# LANGUAGE ScopedTypeVariables #-}

-- We can't block during stanza handling, so we can't run the policy action in
-- there.

module Pontarius.E2E.Xmpp  where

import           Control.Applicative ((<$>))
import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Exception as Ex
import           Control.Monad
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import qualified Data.Map as Map
import           Data.XML.Pickle
import           Data.XML.Types
import qualified Network.Xmpp as Xmpp
import qualified Network.Xmpp.Internal as Xmpp
import           Pontarius.E2E
import           Pontarius.E2E.Serialize
import           Pontarius.E2E.Session
import           Pontarius.E2E.Types
import           Network.Xmpp.Types
import           System.Log.Logger

-- PEM
import qualified Crypto.Types.PubKey.DSA as DSA
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types hiding (Set)
import qualified Data.ByteString.Lazy as BSL
import           Data.PEM

sendE2eMessage xmppSession to msg  = do
    let xml = pickle (xpRoot e2eMessageXml) msg
    case msg of
        E2EDataMessage{} -> Xmpp.sendMessage
                            Xmpp.message{ Xmpp.messageTo = Just to
                                        , Xmpp.messagePayload = [xml]
                                        } xmppSession
        E2EAkeMessage{} -> iqSendHelper xml
        E2EEndSessionMessage -> iqSendHelper xml
    return ()
  where
    iqSendHelper pl = do
        res <- Xmpp.sendIQ' (Just to) Xmpp.Set Nothing pl xmppSession
        case res of
            Just Xmpp.IQResponseResult{} -> return True
            _ -> return False

data Side = Initiator | Responder deriving (Show, Eq)

-- newContext :: DSAKeyPair
--            -> Xmpp.Jid
--            -> Side
--            -> (Maybe BS.ByteString -> IO BS.ByteString)
--            -> (MsgState -> IO ())
--            -> (Bool -> IO ())
--            -> Xmpp.Session
--            -> IO E2EContext
-- newContext dsaKey to side mkSecret oss onAuthChange xmppSession = do
--     sess <- newSession (E2EG e2eDefaultParameters dsaKey) mkSecret oss onAuthChange (sendE2eMessage xmppSession to)
--     _ <- startAke sess (case side of Initiator -> alice; Responder -> bob)
--     return $ E2ECtx sess to

-- recvMessage :: Xmpp.Message
--             -> E2EContext
--             -> IO (Maybe (Either E2EError [BS.ByteString]))
-- recvMessage msg ctx = do
--     if Xmpp.messageFrom msg /= Just (peer ctx)
--         then return Nothing
--         else case unpickle (xpClean e2eMessageXml)
--                            $ Xmpp.messagePayload msg of
--                  Left _ -> return Nothing
--                  Right msg' -> Just <$> takeMessage (e2eSess ctx) msg'

-- sendMsg :: BS.ByteString -> E2EContext -> IO (Either E2EError ())
-- sendMsg msg ctx = sendDataMessage msg (e2eSess ctx)

getKey :: FilePath -> IO (DSA.PublicKey, DSA.PrivateKey)
getKey keyFile = do
    Right ((PEM pName _ bs) : _) <- pemParseLBS `fmap` (BSL.readFile keyFile)
    let Right keysASN1 = decodeASN1 DER (BSL.fromChunks [bs])
    let Right (keyPair ::DSA.KeyPair,  _) = fromASN1 keysASN1
    return (DSA.toPublicKey keyPair, DSA.toPrivateKey keyPair)

withTMVar :: TMVar a -> (a -> IO (a, c)) -> IO c
withTMVar mv f = Ex.bracketOnError (atomically $ takeTMVar mv)
                                   (atomically . putTMVar mv) $
                                   \v -> do
                                       (v', a) <- f v
                                       atomically $ putTMVar mv v'
                                       return a

data E2EConfig = E2ECfg{ peers :: TMVar (Map.Map Xmpp.Jid
                                                 (E2ESession CRandom.SystemRNG))
--                       , xmppSession :: Xmpp.Session
                       , globals :: E2EGlobals
                       , getSecret :: Maybe BS.ByteString -> IO BS.ByteString
                       }

handleE2E policy cfg sem sta = do
    case sta of
        Xmpp.IQRequestS iqr -> case unpickle (xpRoot . xpOption
                                              $ e2eRequestXml)
                                              $ Xmpp.iqRequestPayload iqr of
                                   Left e -> return []
                                   Right Nothing -> return [sta]
                                                    -- Fork to avoid blocking
                                   Right (Just _) -> forkIO (expectSession iqr)
                                                     >> return []
        Xmpp.MessageS msg -> case unpickle (xpOption e2eMessageXml)
                                           (Xmpp.messagePayload msg)
                             of
            Left e -> do
                errorM "Pontarius.Xmpp.E2E" $ "Data Message received from "
                                              ++ show (Xmpp.messageFrom msg)
                                              ++ " produced error"
                                              ++ show e
                return []
            Right Nothing -> return [sta]
            Right (Just msg') | Just from <- Xmpp.messageFrom msg ->
                withTMVar (peers cfg) $ \sess ->
                case Map.lookup from sess of
                    Nothing -> do
                        endE2E from
                        return (sess, []) -- TODO: Check what to do here
                    Just s -> do
                        case msg' of
                            E2EDataMessage dm -> do
                                res <- handleDataMessage s dm
                                return (sess, map (setFrom from) res)
                            E2EAkeMessage am -> do
                                res <- takeMessage s msg'
                                case res of
                                    Left e -> do
                                              errorM "Pontarius.Xmpp.E2E" $
                                                     "AKE Message received from "
                                                     ++ show (Xmpp.messageFrom msg)
                                                     ++ " produced error"
                                                     ++ show e
                                              endE2E from
                                              return (Map.delete from sess, [])
                                    Right r ->

                                        return (sess, [])
                            E2EEndSessionMessage -> do
                                infoM "Pontarius.Xmpp.E2E" $ "E2E session with "
                                      ++ show from ++ " has ended."
                                return (Map.delete from sess, [])

        _ -> return [sta]
  where
    handleDataMessage s dm = do
        res <- takeDataMessage s dm
        case res of
            Left e -> do
                errorM "Pontarius.Xmpp.E2E" $
                    "Receiving data message produced error" ++ show e
                return []
            Right r -> case readStanzas (BS.concat r) of
                Left e -> do
                    errorM "Pontarius.Xmpp.E2E" $
                              "Reading data message produced error" ++ show e
                    return []
                Right r -> do
                    infoM "Pontarius.Xmpp.E2E" $ "e2e in: " ++ show r
                    return r
    setFrom from (MessageS m) = MessageS m{messageFrom = Just from}
    setFrom from (MessageErrorS m) = MessageErrorS m{messageErrorFrom = Just from}
    setFrom from (PresenceS m) = PresenceS m{presenceFrom = Just from}
    setFrom from (PresenceErrorS m) = PresenceErrorS m{presenceErrorFrom = Just from}
    setFrom from (IQRequestS m) = IQRequestS m{iqRequestFrom = Just from}
    setFrom from (IQResultS m) = IQResultS m{iqResultFrom = Just from}
    setFrom from (IQErrorS m) = IQErrorS m{iqErrorFrom = Just from}

    expectSession iqr = do
        case Xmpp.iqRequestFrom iqr
             of Nothing -> return ()
                Just from -> do
                    p <- policy from
                    if p then do
                        s <- newSession (globals cfg) (getSecret cfg)
                               (\_ -> return ()) (\_ -> return ()) $ sm sem from
                        startAke s responder
                        withTMVar (peers cfg) $ \sess ->
                            return (Map.insert from s sess, ())
                        Xmpp.writeStanza sem . Xmpp.IQResultS  $
                            Xmpp.IQResult { Xmpp.iqResultID = Xmpp.iqRequestID iqr
                                          , Xmpp.iqResultTo =
                                              Xmpp.iqRequestFrom iqr
                                          , Xmpp.iqResultFrom = Nothing
                                          , Xmpp.iqResultLangTag = Nothing
                                          , Xmpp.iqResultPayload =
                                              Just $ pickle e2eResponseXml True
                                          }
                        return ()

                        else do
                        Xmpp.writeStanza sem (serviceUnavailable iqr)
                        return ()
    endE2E from = do
        let abortE = pickle endSessionMessageXml ()
        Xmpp.writeStanza sem $ Xmpp.MessageS
            Xmpp.message{ Xmpp.messageTo = Just from
                        , Xmpp.messagePayload = abortE
                        }
    checkNS e f = if nameNamespace (elementName e) == Just e2eNs
                  then f e
                  else return [sta]
    badRequest = iqError errBR
    serviceUnavailable = iqError errSU
    iqError err (Xmpp.IQRequest iqid from _to lang _tp bd) =
        Xmpp.IQErrorS $ Xmpp.IQError iqid Nothing from lang err (Just bd)
    errBR = Xmpp.StanzaError Xmpp.Cancel Xmpp.BadRequest Nothing Nothing
    errSU = Xmpp.StanzaError Xmpp.Cancel Xmpp.ServiceUnavailable Nothing Nothing
    result (Xmpp.IQRequest iqid from _to lang _tp _bd) e =
        Xmpp.IQResultS $ Xmpp.IQResult iqid Nothing from lang e
    sm sem from msg = void . Xmpp.writeStanza sem . Xmpp.MessageS $
                      Xmpp.message{ Xmpp.messageTo = Just from
                                  , Xmpp.messagePayload = pickle e2eMessageXml msg
                                  }

e2eInit :: E2EGlobals
        -> (Maybe BS.ByteString -> IO BS.ByteString)
        -> IO E2EConfig
e2eInit globals sGen  = do
    peers <- newTMVarIO Map.empty
    return $ E2ECfg peers globals sGen

startE2E :: Xmpp.Jid
         -> E2EConfig
         -> (MsgState -> IO ())
         -> Xmpp.Session
         -> IO ()
startE2E to sessions onSS xmppSession = do
    withTMVar (peers sessions) $ \sess -> do
        s <- case Map.lookup to sess of
            --Xmpp.sendIQ
            Nothing -> do
                Xmpp.sendIQ' (Just to) Xmpp.Set Nothing (pickle (xpRoot e2eRequestXml) ()) xmppSession
                newSession (globals sessions) (getSecret sessions) onSS (\_ -> return ()) sm
            Just s -> return s
        Right (msgs, st, smp) <- startAke s initiator
        return (Map.insert to s sess, ())
  where
    sm msg = do
        let xml = pickle e2eMessageXml msg
        Xmpp.sendMessage Xmpp.message{ Xmpp.messageTo = Just to
                                     , Xmpp.messagePayload = xml
                                     } xmppSession
        return ()

sendE2EMsg cfg to sta = do
    ps <- atomically $ readTMVar (peers cfg)
    case Map.lookup to ps of
        Nothing -> return False
        Just p -> do
            res <- sendDataMessage (renderStanza sta) p
            return $ case res of
                Left{} -> False
                Right{} -> True
