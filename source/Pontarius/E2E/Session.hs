{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
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
import qualified Data.Text as Text
import           Data.Text (Text)
import           Control.Applicative ((<$>))
import           Control.Concurrent hiding (yield)
import           Control.Monad
import           Control.Monad.Except
import           Control.Monad.Free
import           Control.Monad.Identity (runIdentity)
import           Control.Monad.Reader (runReaderT)
import           Control.Monad.Writer
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import           System.Log.Logger

import           Pontarius.E2E.AKE (alice, bob)
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Message
import           Pontarius.E2E.Monad
import           Pontarius.E2E.SMP
import           Pontarius.E2E.Types

newSession :: E2EGlobals
           -> (Maybe BS.ByteString -> IO BS.ByteString)
           -> (MsgState -> IO ())
           -> (Bool -> IO ())
           -> (E2EMessage -> IO ())
           -> (BS.ByteString -> IO BS.ByteString)
           -> (PubKey -> BS.ByteString -> BS.ByteString -> IO Bool)
           -> IO (E2ESession CRandom.SystemRNG)
newSession globals sGen oss osmp sm sign' verify' = do
    g <- CRandom.cprgCreate <$> CRandom.createEntropyPool :: IO CRandom.SystemRNG
    let (st, g') = runIdentity $ runRandT g $ runReaderT newState globals
    s <- newMVar $ Done $ Right (st, g')
    return E2ESession{ sE2eGlobals      = globals
                     , sE2eState        = s
                     , sGetSessSecret   = sGen
                     , sOnSendMessage   = sm
                     , sOnStateChange   = oss
                     , sOnSmpAuthChange = osmp
                     , sSign            = sign'
                     , sVerify          = verify'
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
    go (Free (SendMessage m g)) = tell ([], [m]) >> go g
    go (Free (RecvMessage g)) = return $ Wait g
    go (Free (Yield y g)) = tell ([y], []) >> go g
    go (Free (AskSmpSecret mbQs g)) = liftIO (sGetSessSecret s mbQs) >>= go . g
    go (Free (StateChange st g)) = liftIO (sOnStateChange s st) >> go g
    go (Free (SmpAuthenticated a g)) = liftIO (sOnSmpAuthChange s a) >> go g
    go (Free (Log l g)) = liftIO (infoM "Pontarius.Xmpp.E2E" l) >> go g
    go (Free (Sign pt g)) = liftIO (sSign s pt) >>= go . g
    go (Free (Verify pk sig pt g)) = do
        v <- liftIO $ sVerify s pk sig pt
        case v of
            True -> go g
            False -> liftIO $ do
                errorM "Pontarius.Xmpp.E2E" "Verify signature failed"
                return . Done .Left $ ProtocolError SignatureMismatch ""
    go (Pure a) = return $ Done a


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

withSessionState :: E2ESession g
                 -> (E2EState
                     -> g
                     -> IO ((SmpState, g)
                           , Either E2EError b))
                 -> IO (Either E2EError b)
withSessionState session f = modifyMVar (sE2eState session) $ \se ->
    case se of
     Done (Right (s, g)) -> do
         ((smps', g), res) <- f s g
         return (Done (Right (s{smpState = smps'}, g)), res)
     _ -> return (se, Left $ WrongState "withSessionSMP")

advanceSmp :: SmpMessaging t -> (SmpMessaging t, [SmpMessage])
advanceSmp r@(Pure _) = (r, [])
advanceSmp (Free (SendSmpMessage msg r)) = (r, [msg])
advanceSmp r@(Free RecvSmpMessage{} ) = (r, [])


runSMP :: E2ESession g
       -> E2EState
       -> g
       -> SmpMessaging (Either E2EError Bool)
       -> IO ( (SmpState , g)
             , Either E2EError [SmpMessage])
runSMP sess s g m = do
    let (res, msg) = advanceSmp m
    case res of
     (Pure (Left e)) -> return ((SmpDone, g)
                                 , Left e)
     (Pure (Right ver)) -> do
         sOnSmpAuthChange sess ver
         return ( (SmpDone , g)
                , Right msg
                )
     r@(Free RecvSmpMessage{}) -> return ( (SmpInProgress r, g)
                                         , Right msg
                                         )
     (Free (SendSmpMessage msg r)) -> do
        errorM "Pontarius.Xmpp" "Inconsistent state transition in SMP system"
        return ( (SmpDone, g)
               , Left $ WrongState "Inconsistent State transistion")

startSMP :: E2ESession g
         -> (g -> (SMP Bool, g))
         -> IO (Either E2EError [SmpMessage])
startSMP sess m  = withSessionState sess $
       \s g ->
       let (m', g') = m g
       in runSMP sess s g' (execSMP (sE2eGlobals sess) s m')

takeSMPMessage :: CRandom.CPRG g =>
                  E2ESession g
               -> SmpMessage
               -> IO (Either E2EError [SmpMessage])
takeSMPMessage sess msg@SmpMessage1{question = question} = do
    sOnSmpChallenge sess question
    withSessionState sess $ \s g -> do
        let (exps, g') = runRand g mkExponents
            st = SmpGotChallenge $
                 \secret -> execSMP (sE2eGlobals sess) s $ smp2 secret exps msg

        return ((st, g'), Right [])
takeSMPMessage sess msg = withSessionState sess $ \s g ->
    case (smpState s) of
        (SmpInProgress  (Free (RecvSmpMessage n f)))
            | msgNumber msg == n -> runSMP sess s g (f msg)
        st -> do
            errorM "Pontarius.Xmpp" "Received unexpected SMP message"
            return ((st, g), Left $ WrongState "takeSMPMessage: unexpected message")
  where
    msgNumber SmpMessage1{} = 1
    msgNumber SmpMessage2{} = 2
    msgNumber SmpMessage3{} = 3
    msgNumber SmpMessage4{} = 4

respondChallenge :: E2ESession g -> Text -> IO (Either E2EError [SmpMessage])
respondChallenge sess secret = withSessionState sess $ \s g ->
    case (smpState s) of
        (SmpGotChallenge f) -> runSMP sess s g $ f secret
        st -> return ( (st, g)
                     , Left $ WrongState "respondChallenge: No challenge was issued")


mkExponents :: (MonadRandom g m, CRandom.CPRG g, Functor m) =>
               m (Integer,
                  Integer,
                  Integer,
                  Integer,
                  Integer,
                  Integer,
                  Integer,
                  Integer)
mkExponents = do
    i1 <- mkSmpExponent
    i2 <- mkSmpExponent
    i3 <- mkSmpExponent
    i4 <- mkSmpExponent
    i5 <- mkSmpExponent
    i6 <- mkSmpExponent
    i7 <- mkSmpExponent
    i8 <- mkSmpExponent
    return (i1, i2, i3, i4, i5, i6, i7, i8)

initSMP :: CRandom.CPRG g =>
           Maybe Text
        -> Text
        -> E2ESession g
        -> IO (Either E2EError [SmpMessage])
initSMP mbQuestion secret sess = startSMP sess $ \g -> runRand g $ do
    exps <- mkExponents
    return $ smp1 mbQuestion secret exps

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
        Right _ys -> error "Data message yielded multiple results"

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
        (r'@(Done Right{}), ys) -> return $ (r', Right ys)
        (Done (Left e), _ys) -> return (rs, Left e)

initiator :: CRandom.CPRG g => E2E g ()
initiator = alice

responder :: CRandom.CPRG g => E2E g ()
responder = bob
