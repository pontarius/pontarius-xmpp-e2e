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
import           Control.Concurrent hiding (yield)
import qualified Data.Traversable as Traversable
import qualified Control.Exception as Ex
import qualified Data.Map as Map
import           Control.Concurrent.STM
import qualified Network.Xmpp as Xmpp
import           Data.Text (Text)
import           Control.Applicative ((<$>))
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

-- newSession :: E2EGlobals
--            -> Xmpp.Jid

--            -> (PubKey -> BS.ByteString -> BS.ByteString -> IO Bool)
--            -> IO (E2ESession CRandom.SystemRNG)
newSession :: E2EGlobals
           -> E2ECallbacks
           -> Xmpp.Jid
           -> IO (E2ESession CRandom.SystemRNG)
newSession globals cb peer = do
    g <- CRandom.cprgCreate <$> CRandom.createEntropyPool :: IO CRandom.SystemRNG
    let (st, g') = runIdentity $ runRandT g $ runReaderT newState globals
    s <- newTMVarIO $ Done $ Right (st, g')
    return E2ESession{ sE2eGlobals      = globals
                     , sE2eState        = s
                     , sOnStateChange   = onStateChange   cb peer
                     , sOnSmpAuthChange = onSmpAuthChange cb peer
                     , sOnSmpChallenge  = onSmpChallenge  cb peer
                     , sSign            = cSign cb
                     , sVerify          = cVerify cb peer
                     , sPeer            = peer
                     }

advanceMessaging :: E2ESession g
                 -> Messaging (RunState g)
                 -> IO (Run g, ([BS.ByteString], [E2EMessage]))
advanceMessaging s f = do
    res <- runWriterT $ go f
    case res of
        (r@(Done Left{}), _) -> return (r, ([], []))
        (r@(Done Right{}), mys) -> return (r, mys)
        (w@Wait{}, ms) -> return (w, ms)
  where
    go (Free (SendMessage m g)) = tell ([], [m]) >> go g
    go (Free (RecvMessage g)) = return $ Wait g
    go (Free (Yield y g)) = tell ([y], []) >> go g
    go (Free (StateChange os ns g)) = liftIO (sOnStateChange s os ns) >> go g
    go (Free (Log l g)) = liftIO (infoM "Pontarius.Xmpp.E2E" l) >> go g
    go (Free (Sign pt g)) = liftIO (sSign s pt) >>= go . g
    go (Free (Verify pk sig pt g)) = do
        v <- liftIO $ sVerify s pk sig pt
        case v of
            Just info -> go $ g info
            Nothing -> liftIO $ do
                errorM "Pontarius.Xmpp.E2E" "Verify signature failed"
                return . Done .Left $ ProtocolError SignatureMismatch ""
    go (Pure a) = return $ Done a

modifyTMVar :: TMVar a -> (a -> IO (a, c)) -> IO c
modifyTMVar tmvar m =
    Ex.bracketOnError (atomically $ takeTMVar tmvar)
                      (atomically . putTMVar tmvar )
                      (\x -> do
                            (x', y) <- m x
                            atomically $ putTMVar tmvar x'
                            return y)

withSession :: E2ESession g
            -> E2E g ()
            -> IO (Either E2EError ([BS.ByteString], [E2EMessage]))
withSession session go = modifyTMVar (sE2eState session) $ \se -> do
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
withSessionState session f = modifyTMVar (sE2eState session) $ \se ->
    case se of
     Done (Right (s, g)) -> do
         ((smps', g'), res) <- f s g
         return (Done (Right (s{smpState = smps'}, g')), res)
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
runSMP sess _s g m = do
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
     (Free SendSmpMessage{}) -> do
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

resetSession :: E2ESession CRandom.SystemRNG -> IO ()
resetSession session = modifyTMVar_ (sE2eState session) $ \se -> do
    p <- case se of
        Done (Left{}) -> return True
        Done (Right (s,_g))
            | msgState s /= MsgStatePlaintext
              -> do _ <- forkIO $ sOnStateChange session (msgState s)
                                                         MsgStatePlaintext
                    return True
        _ -> return False
    if p then do
        g <- CRandom.cprgCreate <$> CRandom.createEntropyPool
                                        :: IO CRandom.SystemRNG
        let s' = runIdentity $ runRandT g $ runReaderT newState
                                                       (sE2eGlobals session)

        return . Done $ Right s'
        else return se
  where
    modifyTMVar_ tmv m = modifyTMVar tmv (m >=> \x -> return (x, ()))

startAke :: E2ESession CRandom.SystemRNG
         -> E2E CRandom.SystemRNG ()
         -> IO (Either E2EError [E2EMessage])
startAke session side = do
    resetSession session
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
takeMessage sess msg = modifyTMVar (sE2eState sess) $ \rs -> do
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

data SessionState = AkeRunning
                  | NotAuthenticated
                  | AkeError E2EError
                  | Authenticated { sessionPubkey :: !PubKey
                                  , sessionVerifyInfo :: !VerifyInfo
                                  , sessionID :: !BS.ByteString
                                  }
                    deriving (Show)

sessionEnded :: Xmpp.Jid -> E2EContext -> IO ()
sessionEnded j ctx = do
    wasAuthenticated <- atomically $ do
        ps <- takeTMVar $ peers ctx
        case Map.updateLookupWithKey (\ _ _ -> Nothing) j ps of
            (Nothing, _ ) -> putTMVar (peers ctx) ps >> return Nothing
            (Just sess, ps') -> do
                putTMVar (peers ctx) ps'
                st <- sessionState sess
                case st of
                    Authenticated{sessionVerifyInfo = vi} -> return $ Just vi
                    _ -> return Nothing
    case wasAuthenticated of
        Nothing -> return ()
        Just vi -> (onStateChange $ callbacks ctx) j (MsgStateEncrypted vi)
                                                     MsgStateFinished


sessionState :: E2ESession g -> STM SessionState
sessionState sess = do
    st <- readTMVar $ sE2eState sess
    case st of
        Wait{} -> return AkeRunning
        Done (Left e) -> return $ AkeError e
        Done (Right (s, _)) ->
            case msgState s of
                MsgStatePlaintext -> return NotAuthenticated
                MsgStateFinished -> return NotAuthenticated
                MsgStateEncrypted vInfo ->
                    let pk = case theirPubKey s of
                            Nothing -> error "sessionState: No pubkey set"
                            Just pk' -> pk'
                        sid = case ssid s of
                            Nothing -> error "sessionState: No ssid set"
                            Just sid' -> sid'
                    in return $ Authenticated pk vInfo sid

getSessionState :: Xmpp.Jid -> E2EContext -> STM SessionState
getSessionState peer ctx = do
    ps <- readTMVar $ peers ctx
    case Map.lookup peer ps of
        Nothing -> return NotAuthenticated
        Just sess -> sessionState sess


-- | Get session and their status
getSessions :: E2EContext -> STM (Map.Map Xmpp.Jid SessionState)
getSessions ctx = do
    ps <- readTMVar $ peers ctx
    Traversable.forM ps $ sessionState
