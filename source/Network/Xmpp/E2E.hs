{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}

-- We can't block during stanza handling, so we can't run the policy action in
-- there.

module Network.Xmpp.E2E ( e2eInit
                        , startE2E
                        , doEndSession
                        , sendE2EMsg
--                        , getSsid
                        , wasEncrypted
--                        , Network.Xmpp.E2E.getKey
                        , PubKey(..)
                        , E2EGlobals(..)
                        , E2EContext
                        , e2eDefaultParameters
                        , startSMP
                        , answerChallenge
                        ) where

import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Exception as Ex
import           Control.Monad
import           Control.Monad.Except
import           Control.Monad.Trans
import           Control.Monad.Trans.Either
import           Control.Monad.Trans.Maybe
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import           Data.List (find)
import qualified Data.Map as Map
import           Data.Text (Text)
import qualified Data.Text as Text
import           Data.Typeable
import           Data.XML.Pickle
import           Data.XML.Types
import           Network.Xmpp as Xmpp
import qualified Network.Xmpp.Internal as Xmpp
import           Network.Xmpp.Lens
import           Pontarius.E2E.Serialize
import           Pontarius.E2E.Session
import           Pontarius.E2E.Types
import           System.Log.Logger

import           Pontarius.E2E


data Side = Initiator | Responder deriving (Show, Eq)

withTMVar :: TMVar a -> (a -> IO (a, c)) -> IO c
withTMVar mv f = Ex.bracketOnError (atomically $ takeTMVar mv)
                                   (atomically . putTMVar mv) $
                                   \v -> do
                                       (v', a) <- f v
                                       atomically $ putTMVar mv v'
                                       return a

data E2EAnnotation = E2EA { ssidA :: BS.ByteString -- ^ Session ID of the
                          } deriving (Show, Typeable)

handleE2E :: (Jid -> IO (Maybe Bool))
          -> E2EContext
          -> (Xmpp.Stanza -> IO a)
          -> Xmpp.Stanza
          -> [Annotation]
          -> IO [(Xmpp.Stanza, [Annotation])]
handleE2E policy sess out sta _ = do
    case sta of
        Xmpp.IQRequestS iqr -> case unpickle (xpRoot . xpClean . xpOption
                                              $ akeMessageXml)
                                              $ Xmpp.iqRequestPayload iqr of
                                   Left e -> do
                                       errorM "Pontarius.Xmpp.E2E" $
                                              "UnpickleError: "
                                              ++ ppUnpickleError e
                                              ++ "\n in \n" ++ show iqr
                                       return []
                                   Right Nothing -> return [(sta, [])]
                                                    -- Fork to avoid blocking
                                   Right (Just m) -> forkIO (handleAKE iqr m)
                                                     >> return []
        Xmpp.MessageS msg -> eitherT return return $ do
            (msg', from') <- case unpickle (xpOption e2eMessageXml)
                                  (Xmpp.messagePayload msg) of
                        Left e -> do
                            liftIO  . errorM "Pontarius.Xmpp.E2E"
                                $ "Data Message received from "
                                ++ show (Xmpp.messageFrom msg)
                                ++ " produced error"
                                ++ ppUnpickleError e
                            left []
                        Right Nothing -> left [(sta, [])]
                        Right (Just msg') | Just from' <- Xmpp.messageFrom msg
                                            -> return (msg', from')
                                          | otherwise -> do
                                              liftIO . errorM
                                                  "Pontarius.Xmpp.E2E" $
                                                     "Received E2E message "
                                                     ++ "without from"
                                              left []
            guard . (== Just True)  =<< liftIO (policy from')
            liftIO . withTMVar (peers sess) $ \sess' ->
                case Map.lookup from' sess' of
                    Nothing -> do
                        endE2E from'
                        return (sess', []) -- TODO: Check what to do here
                    Just s -> do
                        case msg' of
                            E2EDataMessage dm -> do
                                res <- processDataMessage from' s dm
                                return (sess', res)
                            E2EEndSessionMessage -> do
                                infoM "Pontarius.Xmpp.E2E" $ "E2E session with "
                                      ++ show from' ++ " has ended."
                                return (Map.delete from' sess', [])
                            E2EAkeMessage _ -> do
                                errorM "Pontarius.Xmpp.E2E"
                                       "Got AKE message in message stanza"
                                return (sess', [])

        _ -> return [(sta, [])]
  where
    processDataMessage f s dm = do
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
                Right r' -> liftM concat . forM r' $ \r'' -> do
                    debugM "Pontarius.Xmpp.E2E" $ "e2e in: " ++ show r''
                    case r'' of
                         (Xmpp.MessageS m)
                             | [el] <- messagePayload m
                             , nameNamespace (elementName el) == Just smpNs
                               -> handleSMP m f el >> return []
                         _ -> return [ (set from (Just f) r''
                                     , [Annotation $ E2EA "" ])]

    escape = mzero
    handleSMP iqr f el = case unpickle (xpRoot $ xpUnliftElems xpSmpMessage) el of
        Left e -> do
            errorM "Pontarius.Xmpp" $ "Could not unpickle SMP message"
                                      ++ ppUnpickleError e
            return []
        Right msg -> atomically (readTMVar $ peers sess) >>= \sess' -> do
            case Map.lookup f sess' of
             Nothing -> do
                 errorM "Pontarius.Xmpp" $ "SMP message for nonexistant ssession"
                 return []
             Just s -> do
                 res <- takeSMPMessage s msg
                 case res of
                  Left e -> do
                      errorM "Pontarius.Xmpp" $ "SMP returned error: "++ show e
                      return []
                  Right msgs -> do
                      forM_ msgs $ \msg -> do
                          let pl = pickle (xpUnliftElems xpSmpMessage) msg
                              m = message{ messageTo = Just f
                                         , messagePayload = pl
                                         }

                          ctxSendE2EMsg s (Xmpp.MessageS m)  out
                      return []

    handleAKE iqr msg = void . runMaybeT $ do
        liftIO $ debugM "Pontarius.Xmpp" "Handling AKE..."
        f <- maybe escape return $ Xmpp.iqRequestFrom iqr
        p <- liftIO (policy f)
        case p of
            Nothing -> do
                liftIO $ notAllowed iqr
                escape
            Just False  -> do
                liftIO $ infoM "Pontarius.Xmpp"
                     $ "AKE Policy rejection: " ++ show f
                liftIO $ serviceUnavailable iqr
                escape
            Just True -> return ()
        liftIO $ case msg of
            m@DHCommitMessage{} -> withTMVar (peers sess) $ \sess' -> do
                case Map.lookup f sess' of
                    Nothing -> do
                        mbS <- startSession iqr f m
                        case mbS of
                            Nothing -> return (sess', ())
                            Just s -> return (Map.insert f s sess', ())
                    Just _ -> do
                        errorM "Pontarius.Xmpp.E2E" $
                               "Declining conflicting E2E session from  "
                               ++ show f
                        conflict iqr
                        return (sess', ())
            m@RevealSignatureMessage{} -> withTMVar (peers sess) $ \sess' -> do
                case Map.lookup f sess' of
                    Nothing -> do
                        errorM "Pontarius.Xmpp.E2E" $
                               "Got unexpected RevealSignatureMessage from "
                               ++ show f
                        unexpected iqr
                        return (sess', ())
                    Just s -> do
                        res <- takeAkeMessage s m
                        case res of
                            Left e -> do
                                errorM "Pontarius.Xmpp.E2E" $
                                       "Error in DHCommitMessage from "
                                        ++ show f ++ ": " ++ show e
                                badRequest iqr
                                return (sess', ())
                            Right [r] -> do
                                result iqr . Just
                                    $ pickle (xpRoot akeMessageXml) r
                                return (sess', ())
                            Right _ -> do
                                criticalM "Pontarius.Xmpp.E2E" $
                                          "Handling of DHCommitMessage didn't"
                                           ++ "result in exactly one answer"
                                return (sess', ())
            m -> do
                errorM "Pontarius.Xmpp.E2E" $ "Received unexpected " ++ show m
                                              ++ "in IQ request"
                unexpected iqr
                return ()
    startSession iqr f m = do
        s <- newSession (globals sess) (callbacks sess) f -- globals
        _ <- startAke s responder
        res <- takeAkeMessage s m
        case res of
            Left e -> do
                errorM "Pontarius.Xmpp.E2E" $ "Error in DHCommitMessage from "
                                              ++ show f ++ ": " ++ show e
                badRequest iqr
                return Nothing
            Right [r] -> do
                result iqr (Just $ pickle (xpRoot akeMessageXml) r)
                return $ Just s
            Right _ -> do
                criticalM "Pontarius.Xmpp.E2E"
                          "takeAkeMessage didn't result in exactly one answer"
                return Nothing
    endE2E f = do
        let abortE = pickle endSessionMessageXml ()
        _ <- out $ Xmpp.MessageErrorS
                 Xmpp.messageError{ Xmpp.messageErrorTo = Just f
                                  , Xmpp.messageErrorPayload = abortE
                                  }
        return ()
    badRequest = void . out . iqError errBR
    serviceUnavailable = void . out . iqError errSU
    notAllowed = void . out . iqError errNA
    unexpected = void . out . iqError errUR
    conflict   = void . out . iqError errC
    iqError err (Xmpp.IQRequest iqid f _to l _tp bd _attrs) =
        Xmpp.IQErrorS $ Xmpp.IQError iqid Nothing f l err (Just bd) []
    errBR = Xmpp.StanzaError Xmpp.Modify Xmpp.BadRequest Nothing Nothing
    errSU = Xmpp.StanzaError Xmpp.Cancel Xmpp.ServiceUnavailable Nothing Nothing
    errNA = Xmpp.StanzaError Xmpp.Cancel Xmpp.NotAllowed Nothing Nothing
    errUR = Xmpp.StanzaError Xmpp.Modify Xmpp.UnexpectedRequest Nothing Nothing
    errC  = Xmpp.StanzaError Xmpp.Cancel Xmpp.Conflict Nothing Nothing
    result (Xmpp.IQRequest iqid f _to l _tp _bd _atttrs) e = void . out
                . Xmpp.IQResultS $ Xmpp.IQResult iqid Nothing f l e []

-- | Start an E2E session with peer. This may block indefinitly (because the
-- other side may have to ask the user whether to accept the session). So it
-- can be necessary to run this in another thread or add a timeout.
startE2E :: MonadIO m =>
            Jid
         -> E2EContext
         -> m Bool
startE2E t ctx = maybe (return False) return =<< (runMaybeT $ do
    mbSess <- liftIO . atomically . readTVar $ sessRef ctx
    xmppSession <- case mbSess of
        Nothing -> mzero
        Just s -> return s
    s <- liftIO . withTMVar (peers ctx) $ \sess -> do
        case Map.lookup t sess of
            --Xmpp.sendIQ
            Nothing -> return ()

            Just _s -> doEndSession t xmppSession
        s <- newSession (globals ctx) (callbacks ctx) t
        let sess' = Map.insert t s sess
        return (sess', s)
    liftIO . Ex.handle (\e -> do -- handle asyncronous exceptions
                    doEndSession t xmppSession
                    withTMVar (peers ctx) $
                        \s' -> return (Map.delete t s', ())
                    onStateChange (callbacks ctx) t MsgStatePlaintext
                    Ex.throw (e :: SomeException)
              ) $ do
        Right [E2EAkeMessage msg1] <- startAke s initiator
        res <- runMaybeT $ do
            Just msg2 <- step s msg1 xmppSession
            Nothing <- step s msg2 xmppSession
            return ()
        case res of
            Nothing -> do
                doEndSession t xmppSession
                withTMVar (peers ctx) $ \s' -> return (Map.delete t s', ())
                onStateChange (callbacks ctx) t MsgStatePlaintext
                return False
            Just _ -> return True
    )
  where
    step :: E2ESession CRandom.SystemRNG
            -> E2EAkeMessage
            -> Xmpp.Session
            -> MaybeT IO (Maybe E2EAkeMessage)
    step s msg xmppSession = do
        Right answer <- liftIO $ Xmpp.sendIQ' Nothing (Just t) Xmpp.Set
                                     Nothing (pickle (xpRoot akeMessageXml) msg)
                                     [] xmppSession
        iqr <- case answer of
            IQResponseResult r -> return r
            IQResponseError e -> do
                liftIO . errorM "Pontarius.Xmpp.E2E" $ "Got IQ error " ++ show e
                mzero
        el <- case iqResultPayload iqr of
            Nothing -> do
                liftIO . errorM "Pontarius.Xmpp.E2E" $ "Got empty IQ response"
                mzero
            Just p -> return p
        msg' <- case unpickle (xpRoot akeMessageXml) el of
            Left e -> do
                liftIO . errorM "Pontarius.Xmpp.E2E" $ "Unpickle error: "
                                ++ ppUnpickleError e
                mzero
            Right r -> return r
        res <- liftIO $ takeAkeMessage s msg'
        case res of
            Left e -> do
                liftIO . errorM "Pontarius.Xmpp.E2E" $ "Got protocol error : "
                                ++ show e
                mzero
            Right [r] -> return $ Just r
            Right [] -> return Nothing
            Right _ -> do
                liftIO . criticalM "Pontarius.Xmpp.E2E" $
                          "takeAkeMessage resulted in more than one answer"
                mzero


withSMP :: MonadIO m =>
           Jid
        -> E2EContext
        -> (  E2ESession CRandom.SystemRNG
           -> IO (Either E2EError [SmpMessage]))
        -> m (Either E2EError ())
withSMP peer ctx f = runExceptT $ do
    mbCon <- liftIO . atomically $ readTVar (sessRef ctx)
    con <- case mbCon of
        Nothing -> throwError $ WrongState "No XMPP connection"
        Just c -> return c
    ps <- liftIO $ atomically $ readTMVar (peers ctx)
    p <- case Map.lookup peer ps of
        Nothing -> throwError $ WrongState "No session established"
        Just p' -> return p'
    res <- liftIO $ f p
    msgs <- case res of
        Left e -> throwError e
        Right msgs' -> return msgs'
    forM_ msgs $ \msg -> do
        let pl = pickle (xpUnliftElems xpSmpMessage) msg
            m = message{ messageTo = Just peer
                       , messagePayload = pl
                       }
        liftIO $ Xmpp.sendMessage m con


startSmp :: MonadIO m =>
            Jid
         -> Maybe Text
         -> Text
         -> E2EContext
         -> m (Either E2EError ())
startSmp peer mbQuestion secret ctx =
    withSMP peer ctx $ initSMP mbQuestion secret

answerChallenge :: MonadIO m =>
                   Jid
                -> Text
                -> E2EContext
                -> m (Either E2EError ())
answerChallenge peer secret ctx = withSMP peer ctx $ \s ->
    respondChallenge s secret

doEndSession :: Jid -> Session -> IO ()
doEndSession t xmppSession = do
    let xml = pickle endSessionMessageXml ()
    _ <- Xmpp.sendMessage Xmpp.message{ Xmpp.messageTo = Just t
                                      , Xmpp.messagePayload = xml
                                      } xmppSession
    return ()


ctxSendE2EMsg :: E2ESession g
              -> Xmpp.Stanza
              -> (Xmpp.Stanza -> IO a)
              -> IO (Either XmppFailure ())
ctxSendE2EMsg p sta out = do
    res <- sendDataMessage (renderStanza sta) p
    case res of
        Right [E2EDataMessage msg] -> do
            let xml = pickle dataMessageXml msg
            _ <- out . Xmpp.MessageS $
                    Xmpp.message{ Xmpp.messageTo = view to sta
                                , Xmpp.messagePayload = xml
                                }
            return $ Right ()
        Right _ -> error "sendDataMessage returned wrong message type"
        Left (WrongState _) -> out sta >> mzero
        Left e -> do
            errorM "Pontarius.Xmpp.E2E" $
                   "Error while encrypting stanza: " ++ show e
            return $ Left Xmpp.XmppOtherFailure

sendE2EMsg :: MonadIO m =>
              E2EContext
           -> (Xmpp.Stanza -> IO (Either XmppFailure ()))
           -> Xmpp.Stanza
           -> m (Either XmppFailure ())
sendE2EMsg ctx out sta = maybe (return $ Right ()) return =<< ( runMaybeT $ do
    to' <- case view to sta of
        Nothing -> liftIO (out sta) >> mzero
        Just t -> return t
    -- Hack, TODO: start E2E uses the normal, user-side IQ facilities. In order
    -- to allow the AKE to proceed we need to protect E2E stanzas from being
    -- handled here. The right way to do it would be to do all this on the
    -- plugin-level.
    case sta of
        Xmpp.IQRequestS iqr -> if isE2E $ iqRequestPayload iqr
                          then liftIO (out sta) >> mzero
                          else return ()
        Xmpp.MessageS msg -> case find isE2E $ messagePayload msg of
            Just _ -> liftIO (out sta) >> mzero
            Nothing -> return ()
        _ -> return ()
    ps <- liftIO . atomically $ readTMVar (peers ctx)
    liftIO $ case Map.lookup to' ps of
        Nothing -> out sta
        Just p -> do
            res <- sendDataMessage (renderStanza sta) p
            case res of
                Right [E2EDataMessage msg] -> do
                    let xml = pickle dataMessageXml msg
                    _ <- out . Xmpp.MessageS $
                            Xmpp.message{ Xmpp.messageTo = Just to'
                                        , Xmpp.messagePayload = xml
                                        }
                    return $ Right ()
                Right _ -> error "sendDataMessage returned wrong message type"
                Left (WrongState _) -> out sta >> mzero
                Left e -> do
                    errorM "Pontarius.Xmpp.E2E" $
                           "Error while encrypting stanza: " ++ show e
                    return $ Left Xmpp.XmppOtherFailure
    )
  where
    isE2E e = ((== Just e2eNs) . nameNamespace  . elementName) e

getSsid :: Annotated a -> Maybe BS.ByteString
getSsid = fmap ssidA . Xmpp.getAnnotation

wasEncrypted :: Annotated a -> Bool
wasEncrypted = maybe False (const True) . getSsid

e2eInit :: E2EGlobals
        -> (Jid -> IO (Maybe Bool))
        -> E2ECallbacks
        -> IO (E2EContext, Plugin)
e2eInit gs policy cb = do
    sRef <- newTVarIO Nothing
    ps <- newTMVarIO Map.empty
    let sess = E2EContext{ peers = ps
                         , sessRef = sRef
                         , globals = gs
                         , callbacks = cb
                         }
    let plugin out = do
            return Xmpp.Plugin' { Xmpp.inHandler = handleE2E policy sess out
                                , Xmpp.outHandler = sendE2EMsg sess out
                                , Xmpp.onSessionUp = \s ->
                                atomically $ writeTVar sRef $ Just s
                                }
    return (sess, plugin)
