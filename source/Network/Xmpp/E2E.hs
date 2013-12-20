{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- We can't block during stanza handling, so we can't run the policy action in
-- there.

module Network.Xmpp.E2E ( e2eInit
                        , startE2E
                        , doEndSession
                        , sendE2EMsg
                        , getSsid
                        , wasEncrypted
                        , Network.Xmpp.E2E.getKey
                        ) where

import           Control.Applicative ((<$>))
import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Exception as Ex
import           Control.Monad
import           Control.Monad.Trans
import           Control.Monad.Trans.Either
import           Control.Monad.Trans.Maybe
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import           Data.List (find)
import qualified Data.Map as Map
import           Data.Typeable
import           Data.XML.Pickle
import           Data.XML.Types
import qualified Network.Xmpp as Xmpp
import           Network.Xmpp.Concurrent.Types as Xmpp
import qualified Network.Xmpp.Internal as Xmpp
import           Network.Xmpp.Lens
import           Network.Xmpp.Types as Xmpp
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

data Side = Initiator | Responder deriving (Show, Eq)

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

data E2EAnnotation = E2EA { ssidA :: BS.ByteString -- ^ Session ID of the
                          } deriving (Show, Typeable)

handleE2E :: (Jid -> IO (Maybe Bool))
             -> E2EContext
             -> (Stanza -> IO a)
             -> Stanza
             -> [Annotation]
             -> IO [Annotated Stanza]
handleE2E policy sess out sta as = do
    case sta of
        Xmpp.IQRequestS iqr -> case unpickle (xpRoot . xpOption
                                              $ akeMessageXml)
                                              $ Xmpp.iqRequestPayload iqr of
                                   Left e -> do
                                       errorM "Pontarius.Xmpp.E2E" $
                                              "UnpickleError: " ++ show e
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
                                ++ show e
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
                        _ -> left [(sta, [])]
            guard . (== Just True)  =<< liftIO (policy from')
            liftIO . withTMVar (peers sess) $ \sess ->
                case Map.lookup from' sess of
                    Nothing -> do
                        endE2E from'
                        return (sess, []) -- TODO: Check what to do here
                    Just s -> do
                        case msg' of
                            E2EDataMessage dm -> do
                                res <- processDataMessage from' s dm
                                return (sess, res)
                            E2EEndSessionMessage -> do
                                infoM "Pontarius.Xmpp.E2E" $ "E2E session with "
                                      ++ show from' ++ " has ended."
                                return (Map.delete from' sess, [])

        _ -> return [(sta, [])]
  where
    processDataMessage f s dm = do
        res <- takeDataMessage s dm
        case res of
            Left e -> do
                errorM "Pontarius.Xmpp.E2E" $
                    "Receiving data message produced error" ++ show e
                return []
            Right (r, sid) -> case readStanzas r of
                Left e -> do
                    errorM "Pontarius.Xmpp.E2E" $
                              "Reading data message produced error" ++ show e
                    return []
                Right r' -> do
                    infoM "Pontarius.Xmpp.E2E" $ "e2e in: " ++ show r
                    return $ (\st -> ( set from (Just f) st
                                     , [Annotation $ E2EA sid]))
                                    <$> r'
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
            m@DHCommitMessage{} -> withTMVar (peers sess) $ \sess -> do
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
            m@RevealSignatureMessage{} -> withTMVar (peers sess) $ \sess -> do
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
        s <- newSession (globals sess) (getCtxSecret sess)
                               (\_ -> return ()) (\_ -> return ()) (\_ -> return ()) (getPKey sess)
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
        out $ Xmpp.MessageS Xmpp.message{ Xmpp.messageTo = Just from
                                        , Xmpp.messagePayload = abortE
                                        }
        return ()
    checkNS e f = if nameNamespace (elementName e) == Just e2eNs
                  then f e
                  else return [sta]
    badRequest = out . iqError errBR
    serviceUnavailable = out . iqError errSU
    notAllowed = out . iqError errNA
    unexpected = out . iqError errUR
    conflict   = out . iqError errC
    iqError err (Xmpp.IQRequest iqid from _to lang _tp bd) =
        Xmpp.IQErrorS $ Xmpp.IQError iqid Nothing from lang err (Just bd)
    errBR = Xmpp.StanzaError Xmpp.Modify Xmpp.BadRequest Nothing Nothing
    errSU = Xmpp.StanzaError Xmpp.Cancel Xmpp.ServiceUnavailable Nothing Nothing
    errNA = Xmpp.StanzaError Xmpp.Cancel Xmpp.NotAllowed Nothing Nothing
    errUR = Xmpp.StanzaError Xmpp.Modify Xmpp.UnexpectedRequest Nothing Nothing
    errC  = Xmpp.StanzaError Xmpp.Cancel Xmpp.Conflict Nothing Nothing
    result (Xmpp.IQRequest iqid from _to lang _tp _bd) e = out
                . Xmpp.IQResultS $ Xmpp.IQResult iqid Nothing from lang e

e2eInit :: E2EGlobals
        -> (Jid -> IO (Maybe Bool))
        -> (Maybe BS.ByteString -> IO BS.ByteString)
        -> (Fingerprint -> IO (Maybe Pubkey))
        -> IO (E2EContext, Plugin)
e2eInit globals policy sGen gpk = do
    sessRef <- newTVarIO Nothing
    peers <- newTMVarIO Map.empty
    let sess = E2EContext peers sessRef globals sGen gpk
    let plugin out = do
            return Xmpp.Plugin' { Xmpp.inHandler = handleE2E policy sess out
                                , Xmpp.outHandler = sendE2EMsg sess out
                                , Xmpp.onSessionUp = \sess ->
                                atomically $ writeTVar sessRef $ Just sess
                                }
    return (sess, plugin)



-- | Start an E2E session with peer. This may block indefinitly (because the
-- other side may have to ask the user whether to accept the session). So it
-- can be necessary to run this in another thread or add a timeout.
startE2E :: MonadIO m =>
            Jid
            -> E2EContext
            -> (MsgState -> IO ())
            -> m Bool
startE2E to ctx onSS = maybe (return False) return =<< (runMaybeT $ do
    mbSess <- liftIO . atomically . readTVar $ sessRef ctx
    xmppSession <- case mbSess of
        Nothing -> mzero
        Just s -> return s
    s <- liftIO . withTMVar (peers ctx) $ \sess -> do
        case Map.lookup to sess of
            --Xmpp.sendIQ
            Nothing -> return ()

            Just s -> doEndSession to xmppSession
        s <- newSession (globals ctx) (getCtxSecret ctx) onSS
                    (\_ -> return ()) (\_ -> return ()) (getPKey ctx)
        let sess' = Map.insert to s sess
        return (sess', s)
    liftIO . Ex.handle (\e -> do -- handle asyncronous exceptions
                    doEndSession to xmppSession
                    withTMVar (peers ctx) $
                        \s -> return (Map.delete to s, ())
                    onSS MsgStatePlaintext
                    Ex.throw (e :: SomeException)
              ) $ do
        Right ([E2EAkeMessage msg1], st, smp) <- startAke s initiator
        res <- runMaybeT $ do
            Just msg2 <- step s msg1 xmppSession
            Nothing <- step s msg2 xmppSession
            return ()
        case res of
            Nothing -> do
                doEndSession to xmppSession
                withTMVar (peers ctx) $ \s -> return (Map.delete to s, ())
                onSS MsgStatePlaintext
                return False
            Just _ -> return True
    )
  where
    step :: E2ESession CRandom.SystemRNG
            -> E2EAkeMessage
            -> Xmpp.Session
            -> MaybeT IO (Maybe E2EAkeMessage)
    step s msg xmppSession = do
        Right answer <- liftIO $ Xmpp.sendIQ' Nothing (Just to) Xmpp.Set
                                     Nothing (pickle (xpRoot akeMessageXml) msg)
                                     xmppSession
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

sendE2EMsg ctx out sta = maybe (return $ Right ()) return =<< ( runMaybeT $ do
    to' <- case view to sta of
        Nothing -> liftIO (out sta) >> mzero
        Just t -> return t
    -- Hack, TODO: start E2E uses the normal, user-side IQ facilities. In order
    -- to allow the AKE to proceed we need to protect E2E stanzas from being
    -- handled here. The right way to do it would be to do all this on the
    -- plugin-level.
    case sta of
        IQRequestS iqr -> if isE2E $ iqRequestPayload iqr
                          then liftIO (out sta) >> mzero
                          else return ()
        MessageS msg -> case find isE2E $ messagePayload msg of
            Just _ -> liftIO (out sta) >> mzero
            Nothing -> return ()
        _ -> return ()
    ps <- liftIO . atomically $ readTMVar (peers ctx)
    liftIO $ case Map.lookup to' ps of
        Nothing -> out sta
        Just p -> do
            res <- sendDataMessage (renderStanza sta) p
            case res of
                Right ([E2EDataMessage msg], _, _) -> do
                    let xml = pickle dataMessageXml msg
                    out  . Xmpp.MessageS $
                            Xmpp.message{ Xmpp.messageTo = Just to'
                                        , Xmpp.messagePayload = xml
                                        }
                    return $ Right ()
                Left e -> do
                    errorM "Pontarius.Xmpp.E2E" $
                           "Error while encrypting stanza: " ++ show e
                    return $ Left Xmpp.XmppOtherFailure
    )
  where
    isE2E e = ((== Just e2eNs) . nameNamespace  . elementName) e

getSsid :: Annotated a -> Maybe BS.ByteString
getSsid = fmap ssidA . getAnnotation

wasEncrypted :: Annotated a -> Bool
wasEncrypted = maybe False (const True) . getSsid
