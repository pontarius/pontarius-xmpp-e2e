{-# LANGUAGE TupleSections #-}
{-# LANGUAGE RecordWildCards #-}
module Pontarius.E2E.Session
       -- ( newSession
       -- , initiator
       -- , responder
       -- , E2ESession
       -- , endSession
       -- , startAke
       -- , takeAkeMessage
       -- , takeDataMessage
       -- , takeMessage
       -- , sendDataMessage
       -- )

       where
import           Control.Applicative((<$>))
import           Control.Concurrent hiding (yield)
import qualified Control.Exception as Ex
import           Control.Monad
import           Control.Monad.Error
import           Control.Monad.Free
import           Control.Monad.Identity (runIdentity)
import           Control.Monad.Reader (runReaderT)
import           Control.Monad.Writer
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import           Data.Maybe (listToMaybe)
import           System.Log.Logger

import           Pontarius.E2E.Monad
import           Pontarius.E2E.Types
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Message
import           Pontarius.E2E.AKE (alice, bob)

newSession :: E2EGlobals
           -> (Maybe BS.ByteString -> IO BS.ByteString)
           -> (MsgState -> IO ())
           -> (Bool -> IO ())
           -> (E2EMessage -> IO ())
           -> (BS.ByteString -> IO BS.ByteString)
           -> (PubKey -> BS.ByteString -> BS.ByteString -> IO Bool)
           -> IO (E2ESession CRandom.SystemRNG)
newSession globals sGen oss osmp sm sign verify = do
    g <- CRandom.cprgCreate <$> CRandom.createEntropyPool :: IO CRandom.SystemRNG
    let (st, g') = runIdentity $ runRandT g $ runReaderT newState globals
    s <- newMVar $ Done $ Right (st, g')
    return E2ESession{ sE2eGlobals      = globals
                     , sE2eState        = s
                     , sGetSessSecret   = sGen
                     , sOnSendMessage   = sm
                     , sOnStateChange   = oss
                     , sOnSmpAuthChange = osmp
                     , sSign            = sign
                     , sVerify          = verify
                     }

advanceMessaging :: E2ESession g
                 -> Messaging (RunState g)
                 -> IO (Run g, ([BS.ByteString], [E2EMessage]))
advanceMessaging s f = do
    res <- runWriterT $ go f
    case res of
        (r@(Done Left{}), _) -> return (r, ([], []))
        (r@(Done Right{}), mys@(_,ms)) -> do
            forM_ ms $ sOnSendMessage s
            return (r, mys)
        (w@Wait{}, ms) -> return (w, ms)
  where
    go (Free (SendMessage m f)) = tell ([], [m]) >> go f
    go rcv@(Free (RecvMessage f)) = return $ Wait f
    go (Free (Yield y f)) = tell ([y], []) >> go f
    go (Free (AskSmpSecret mbQs f)) = liftIO (sGetSessSecret s mbQs) >>= go . f
    go (Free (StateChange st f)) = liftIO (sOnStateChange s st) >> go f
    go (Free (SmpAuthenticated a f)) = liftIO (sOnSmpAuthChange s a) >> go f
    go (Free (Log l f)) = liftIO (infoM "Pontarius.Xmpp.E2E" l) >> go f
    go (Free (Sign pt f)) = liftIO (sSign s pt) >>= go . f
    go (Free (Verify pk sig pt f)) = do
        v <- liftIO $ sVerify s pk sig pt
        case v of
            True -> go f
            False -> liftIO $ do
                errorM "Pontarius.Xmpp.E2E" "Verify signature failed"
                return . Done .Left $ ProtocolError SignatureMismatch ""
    go p@(Pure a) = return $ Done a


withSession :: E2ESession g
            -> E2E g ()
            -> IO (Either E2EError ([BS.ByteString], [E2EMessage]))
withSession session go = modifyMVar (sE2eState session) $ \se -> do
    case se of
        Done (Right (s, g)) -> do
            res <- advanceMessaging session $ execE2E (sE2eGlobals session) s g go
            case res of
                (Done (Left e), _) -> return (se, Left e)
                (r@(Done Right{}), ms) -> return (r, Right ms)
                (w@Wait{}, ms) -> return (w, Right ms)
        _ -> return (se, Left $ WrongState "withSession")

endSession :: E2ESession CRandom.SystemRNG -> IO ()
endSession session = modifyMVar_ (sE2eState session) $ \se -> do
    p <- case se of
        Wait _ -> do
            sOnSendMessage session E2EEndSessionMessage
            return True
        Done (Right (s,_g)) -> return (msgState s /= MsgStatePlaintext)
        Done (Left{}) -> return True
    if p then do
        g <- CRandom.cprgCreate <$> CRandom.createEntropyPool
                                        :: IO CRandom.SystemRNG
        let s' = runIdentity $ runRandT g $ runReaderT newState
                                                       (sE2eGlobals session)
        return . Done $ Right s'
        else return se

startAke :: E2ESession CRandom.SystemRNG
         -> E2E CRandom.SystemRNG ()
         -> IO (Either E2EError [E2EMessage])
startAke session side = do
    endSession session
    fmap snd <$>withSession session side

sendDataMessage :: BS.ByteString
                -> E2ESession g
                -> IO (Either E2EError [E2EMessage])
sendDataMessage msg session = liftM (fmap snd) . withSession session $ do
    m <- encryptDataMessage msg
    sendMessage $ E2EDataMessage m

handleDataMessage :: CRandom.CPRG g => DataMessage -> E2E g ()
handleDataMessage msg = do
    msgPl <- decryptDataMessage msg
    unless (BS.null msgPl) $ yield msgPl

takeAkeMessage :: CRandom.CPRG g =>
                  E2ESession g
               -> E2EAkeMessage
               -> IO (Either E2EError [E2EAkeMessage])
takeAkeMessage sess msg  =
    fmap (map unE2EAkeMessage . snd) <$> takeMessage sess (E2EAkeMessage msg)

takeDataMessage :: CRandom.CPRG g =>
                   E2ESession g
                   -> DataMessage
                   -> IO (Either E2EError BS.ByteString)
takeDataMessage sess msg = do
    res <- takeMessage sess $ E2EDataMessage msg
    case res of
        Left e -> return $ Left e
        Right ([y],[]) -> return $ Right y
        Right ys -> error "Data message yielded multiple results"

takeMessage :: CRandom.CPRG g =>
               E2ESession g
            -> E2EMessage
            -> IO (Either E2EError ([BS.ByteString], [E2EMessage]))
takeMessage sess msg = modifyMVar (sE2eState sess) $ \rs -> do
    let r = case rs of
            -- There's no suspended computation, so we can start a new one
            Done (Right (st, g)) -> case msg of
                E2EDataMessage msg' -> execE2E (sE2eGlobals sess) st g
                                         $ handleDataMessage msg'
                _ -> error "not yet implemented" -- TODO
            -- We have a suspended computation that expects a message, so we
            -- pass it the message
            Done (Left{}) -> return (Left (WrongState "Session is in error state"))
            Wait rcm -> rcm msg
    res <- advanceMessaging sess r
    case res of
        (w@Wait{}, ys) -> return $ (w, Right ys)
        (r@(Done Right{}), ys) -> return $ (r, Right ys)
        (Done (Left e), ys) -> return (rs, Left e)

initiator :: CRandom.CPRG g => E2E g ()
initiator = alice

responder :: CRandom.CPRG g => E2E g ()
responder = bob
