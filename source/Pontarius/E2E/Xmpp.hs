{-# LANGUAGE ScopedTypeVariables #-}

-- We can't block during stanza handling, so we can't run the policy action in
-- there.

module Pontarius.E2E.Xmpp  where

import           Control.Applicative ((<$>))
import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Exception as Ex
import           Control.Monad
import           Control.Monad.Trans
import           Control.Monad.Trans.Maybe
import           Control.Monad.Trans.Either
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import qualified Data.Map as Map
import           Data.XML.Pickle
import           Data.XML.Types
import qualified Network.Xmpp as Xmpp
import qualified Network.Xmpp.Internal as Xmpp
import           Network.Xmpp.Types
import           Pontarius.E2E
import           Pontarius.E2E.Serialize
import           Pontarius.E2E.Session
import           Pontarius.E2E.Types
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
                                              $ akeMessageXml)
                                              $ Xmpp.iqRequestPayload iqr of
                                   Left e -> do
                                       errorM "Pontarius.Xmpp.E2E" $
                                              "UnpickleError: " ++ show e
                                       return []
                                   Right Nothing -> return [sta]
                                                    -- Fork to avoid blocking
                                   Right (Just m) -> forkIO (handleAKE iqr m)
                                                     >> return []
        Xmpp.MessageS msg -> eitherT return return $ do
            (msg', from) <- case unpickle (xpOption e2eMessageXml)
                                  (Xmpp.messagePayload msg) of
                        Left e -> do
                            liftIO  . errorM "Pontarius.Xmpp.E2E"
                                $ "Data Message received from "
                                ++ show (Xmpp.messageFrom msg)
                                ++ " produced error"
                                ++ show e
                            left []
                        Right Nothing -> left [sta]
                        Right (Just msg') | Just f <- Xmpp.messageFrom msg
                                            -> return (msg', f)
                                          | otherwise -> do
                                              liftIO . errorM
                                                  "Pontarius.Xmpp.E2E" $
                                                     "Received E2E message "
                                                     ++ "without from"
                                              left []
                        _ -> left [sta]
            guard . (== Just True)  =<< liftIO (policy from)
            liftIO . withTMVar (peers cfg) $ \sess ->
                case Map.lookup from sess of
                    Nothing -> do
                        endE2E from
                        return (sess, []) -- TODO: Check what to do here
                    Just s -> do
                        case msg' of
                            E2EDataMessage dm -> do
                                res <- handleDataMessage s dm
                                return (sess, map (setFrom from) res)
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
            Right r -> case readStanzas r of
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
    escape = mzero
    handleAKE iqr msg = void . runMaybeT $ do
        from <- maybe escape return $ Xmpp.iqRequestFrom iqr
        p <- liftIO (policy from)
        case p of
            Nothing -> do
                liftIO $ notAllowed iqr
                escape
            Just False  -> do
                liftIO $ serviceUnavailable iqr
                escape
            Just True -> return ()

        liftIO $ case msg of
            m@DHCommitMessage{} -> withTMVar (peers cfg) $ \sess -> do
                case Map.lookup from sess of
                    Nothing -> do
                        mbS <- startSession iqr from m
                        case mbS of
                            Nothing -> return (sess, ())
                            Just s -> return (Map.insert from s sess, ())
                    Just _ -> do
                        errorM "Pontarius.Xmpp.E2E" $
                               "Declining conflicting E2E session from  "
                               ++ show from
                        conflict iqr
                        return (sess, ())
            m@RevealSignatureMessage{} -> withTMVar (peers cfg) $ \sess -> do
                case Map.lookup from sess of
                    Nothing -> do
                        errorM "Pontarius.Xmpp.E2E" $
                               "Got unexpected RevealSignatureMessage from "
                               ++ show from
                        unexpected iqr
                        return (sess, ())
                    Just s -> do
                        res <- takeAkeMessage s m
                        case res of
                            Left e -> do
                                errorM "Pontarius.Xmpp.E2E" $
                                       "Error in DHCommitMessage from "
                                        ++ show from ++ ": " ++ show e
                                badRequest iqr
                                return (sess, ())
                            Right (Just r) -> do
                                result iqr . Just
                                    $ pickle (xpRoot akeMessageXml) r
                                return (sess, ())
            m -> do
                errorM "Pontarius.Xmpp.E2E" $ "Received unexpected " ++ show m
                                              ++ "in IQ request"
                unexpected iqr
                return ()


    startSession iqr from m = do
        s <- newSession (globals cfg) (getSecret cfg)
                               (\_ -> return ()) (\_ -> return ()) (\_ -> return ())
        startAke s responder
        res <- takeAkeMessage s m
        case res of
            Left e -> do
                errorM "Pontarius.Xmpp.E2E" $ "Error in DHCommitMessage from "
                                              ++ show from ++ ": " ++ show e
                badRequest iqr
                return Nothing
            Right (Just r) -> do
                result iqr (Just $ pickle (xpRoot akeMessageXml) r)
                return $ Just s
    endE2E from = do
        let abortE = pickle endSessionMessageXml ()
        Xmpp.writeStanza sem $ Xmpp.MessageS
            Xmpp.message{ Xmpp.messageTo = Just from
                        , Xmpp.messagePayload = abortE
                        }
        return ()
    checkNS e f = if nameNamespace (elementName e) == Just e2eNs
                  then f e
                  else return [sta]
    badRequest = Xmpp.writeStanza sem . iqError errBR
    serviceUnavailable = Xmpp.writeStanza sem . iqError errSU
    notAllowed = Xmpp.writeStanza sem . iqError errNA
    unexpected = Xmpp.writeStanza sem . iqError errUR
    conflict   = Xmpp.writeStanza sem . iqError errC
    iqError err (Xmpp.IQRequest iqid from _to lang _tp bd) =
        Xmpp.IQErrorS $ Xmpp.IQError iqid Nothing from lang err (Just bd)
    errBR = Xmpp.StanzaError Xmpp.Modify Xmpp.BadRequest Nothing Nothing
    errSU = Xmpp.StanzaError Xmpp.Cancel Xmpp.ServiceUnavailable Nothing Nothing
    errNA = Xmpp.StanzaError Xmpp.Cancel Xmpp.NotAllowed Nothing Nothing
    errUR = Xmpp.StanzaError Xmpp.Modify Xmpp.UnexpectedRequest Nothing Nothing
    errC  = Xmpp.StanzaError Xmpp.Cancel Xmpp.Conflict Nothing Nothing
    result (Xmpp.IQRequest iqid from _to lang _tp _bd) e = Xmpp.writeStanza sem
                . Xmpp.IQResultS $ Xmpp.IQResult iqid Nothing from lang e


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
    s <- withTMVar (peers sessions) $ \sess -> do
        case Map.lookup to sess of
            --Xmpp.sendIQ
            Nothing -> return ()

            Just s -> doEndSession to xmppSession
        s <- newSession (globals sessions) (getSecret sessions) onSS
                    (\_ -> return ()) (\_ -> return ())
        let sess' = Map.insert to s sess
        return (sess', s)
    Right ([E2EAkeMessage msg1], st, smp) <- startAke s initiator
    res <- runMaybeT $ do
        Just msg2 <- step s msg1
        Nothing <- step s msg2
        return ()
    case res of
        Nothing -> do
            doEndSession to xmppSession
            withTMVar (peers sessions) $ \s -> return (Map.delete to s, ())
            onSS MsgStatePlaintext
        Just _ -> return ()
  where
    step :: E2ESession CRandom.SystemRNG
            -> E2EAkeMessage
            -> MaybeT IO (Maybe E2EAkeMessage)
    step s msg = do
        Just answer' <- liftIO $ Xmpp.sendIQ Nothing (Just to) Xmpp.Set Nothing
                     (pickle (xpRoot akeMessageXml) msg) xmppSession
        answer <- liftIO . atomically $ takeTMVar answer'
        iqr <- case answer of
            IQResponseResult r -> return r
            IQResponseError e -> do
                liftIO . errorM "Pontarius.Xmpp.E2E" $ "Got IQ error " ++ show e
                mzero
            IQResponseTimeout -> do
                liftIO $ errorM "Pontarius.Xmpp.E2E" "Got IQ timeout "
                mzero
        el <- case iqResultPayload iqr of
            Nothing -> do
                liftIO . errorM "Pontarius.Xmpp.E2E" $ "Got empty IQ response"
                mzero
            Just p -> return p
        msg <- case unpickle (xpRoot akeMessageXml) el of
            Left e -> do
                liftIO . errorM "Pontarius.Xmpp.E2E" $ "Unpickle error: "
                                ++ ppUnpickleError e
                mzero
            Right r -> return r
        res <- liftIO $ takeAkeMessage s msg
        case res of
            Left e -> do
                liftIO . errorM "Pontarius.Xmpp.E2E" $ "Got protocol error : "
                                ++ show e
                mzero
            Right r -> return r


doEndSession to xmppSession = do
    let xml = pickle endSessionMessageXml ()
    Xmpp.sendMessage Xmpp.message{ Xmpp.messageTo = Just to
                                 , Xmpp.messagePayload = xml
                                 } xmppSession
    return ()

sendE2EMsg cfg to sta xmppSession = do
    ps <- atomically $ readTMVar (peers cfg)
    case Map.lookup to ps of
        Nothing -> return False
        Just p -> do
            res <- sendDataMessage (renderStanza sta) p
            case res of
                Right ([E2EDataMessage msg], _, _) -> do
                    let xml = pickle dataMessageXml msg
                    Xmpp.sendMessage Xmpp.message{ Xmpp.messageTo = Just to
                                                 , Xmpp.messagePayload = xml
                                                 } xmppSession
                _ -> return False
