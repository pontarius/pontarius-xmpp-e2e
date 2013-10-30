{-# LANGUAGE RecordWildCards #-}
module Pontarius.E2E.Session
       ( newSession
       , initiator
       , responder
       , E2ESession
       , endSession
       , startAke
       , takeAkeMessage
       , takeDataMessage
       , takeMessage
       , sendDataMessage
       )

       where
import           Control.Applicative((<$>))
import           Control.Concurrent hiding (yield)
import qualified Control.Exception as Ex
import           Control.Monad
import           Control.Monad.Identity (runIdentity)
import           Control.Monad.Reader (runReaderT)
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS

import           Pontarius.E2E.Monad
import           Pontarius.E2E.Types
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Message
import           Pontarius.E2E.AKE (alice, bob)

data E2ESession g = E2ESession { e2eGlobals :: E2EGlobals
                               , e2eState :: MVar (Either (RunState g)
                                                  (E2EState, g))
                               , getSecret :: Maybe BS.ByteString
                                              -> IO BS.ByteString
                               , onSendMessage :: E2EMessage -> IO ()
                               , onStateChange :: MsgState -> IO ()
                               , onSmpAuthChange :: Bool -> IO ()
                               }

-- | Run a computation, accumulating all output until it expects more input ends.
runMessaging :: RunState g
             -> Either E2EError ( Either (RunState g) (E2EState, g)
                                , [BS.ByteString]
                                , [E2EMessage]
                                , Maybe MsgState
                                , Maybe Bool
                                )
runMessaging = go id id Nothing Nothing
  where
    go _ys _os _s _a (Return ((Left e, _st'), _g'))  = Left e
    go ys os s a (Return ((Right () , st'), g')) = Right ( Right (st', g')
                                                         , ys []
                                                         , os []
                                                         , s
                                                         , a
                                                         )
    go ys os s a (Yield y f) = go (ys . (y:)) os s a f
    go ys os s a (SendMessage outMsg f) = go ys (os . (outMsg:)) s a f
    go ys os s a rc@(RecvMessage{}) = Right (Left rc , ys [], os [], s, a)
    go ys os s a as@(AskSmpSecret{}) = Right (Left as , ys [], os [], s, a)
    go ys os _s a (StateChange st f) = go ys os (Just st) a f
    go ys os s _a (SmpAuthenticated auth f) = go ys os s (Just auth) f

newSession :: E2EGlobals
           -> (Maybe BS.ByteString -> IO BS.ByteString)
           -> (MsgState -> IO ())
           -> (Bool -> IO ())
           -> (E2EMessage -> IO ())
           -> IO (E2ESession CRandom.SystemRNG)
newSession globals sGen oss osmp sm = do
    g <- CRandom.cprgCreate <$> CRandom.createEntropyPool :: IO CRandom.SystemRNG
    let (st, g') = runIdentity $ runRandT g $ runReaderT  newState globals
    s <- newMVar $ Right (st, g')
    return E2ESession{ e2eGlobals      = globals
                     , e2eState        = s
                     , getSecret       = sGen
                     , onSendMessage   = sm
                     , onStateChange   = oss
                     , onSmpAuthChange = osmp
                     }

withSession :: E2ESession g
            -> E2E g ()
            -> IO (Either E2EError ([E2EMessage], Maybe MsgState, Maybe Bool))
withSession session go = do
    se <- takeMVar $ e2eState session
    case se of
        Left _ -> return . Left $ WrongState "withSession"
        Right (s, g) -> case runMessaging $ runE2E (e2eGlobals session) s g go of
            Left e -> return $ Left e
            Right (rc, _ys, os, ss, a) -> do
                forM_ os (onSendMessage session)
                maybe (return ()) (onStateChange session) ss
                maybe (return ()) (onSmpAuthChange session) a
                putMVar (e2eState session) rc
                return $ Right (os, ss, a)

endSession :: E2ESession CRandom.SystemRNG -> IO ()
endSession session = do
    se <- takeMVar $ e2eState session
    p <- case se of
        Left _ -> do
            onSendMessage session E2EEndSessionMessage
            return True
        Right (s,_g) -> return (msgState s == MsgStatePlaintext)
    if p then do
        g <- CRandom.cprgCreate <$> CRandom.createEntropyPool
                                        :: IO CRandom.SystemRNG
        let s' = runIdentity $ runRandT g $ runReaderT newState
                                                       (e2eGlobals session)
        putMVar (e2eState session) (Right s')
        else putMVar (e2eState session) se


startAke :: E2ESession CRandom.SystemRNG
         -> E2E CRandom.SystemRNG ()
         -> IO (Either E2EError ([E2EMessage], Maybe MsgState, Maybe Bool))
startAke session side = do
    endSession session
    withSession session side

sendDataMessage :: BS.ByteString
                -> E2ESession g
                -> IO (Either E2EError ([E2EMessage], Maybe MsgState, Maybe Bool))
sendDataMessage msg session = withSession session $ do
    m <- encryptDataMessage msg
    sendMessage $ E2EDataMessage m



handleDataMessage :: CRandom.CPRG g => DataMessage -> E2E g ()
handleDataMessage msg = do
    msgPl <- decryptDataMessage msg
    unless (BS.null msgPl) $ yield msgPl


takeAkeMessage :: CRandom.CPRG g
               => E2ESession g
               -> E2EAkeMessage
               -> IO (Either E2EError [BS.ByteString])
takeAkeMessage sess = takeMessage sess . E2EAkeMessage


takeDataMessage :: CRandom.CPRG g
               => E2ESession g
               -> DataMessage
               -> IO (Either E2EError [BS.ByteString])
takeDataMessage sess = takeMessage sess . E2EDataMessage

takeMessage :: CRandom.CPRG g
            => E2ESession g
            -> E2EMessage
            -> IO (Either E2EError [BS.ByteString])
takeMessage (E2ESession globals s _sGen sm oss osmp) msg =
    Ex.bracketOnError (takeMVar s)
                      (putMVar s) $ \rs -> do
    let r = case rs of
            -- There's no suspended computation, so we can start a new one
            Right (st, g) -> case msg of
                E2EDataMessage msg' -> runE2E globals st g $ handleDataMessage msg'
                _ -> error "not yet implemented" -- TODO
            -- We have a suspended computation that expects a message, so we pass it the message
            Left (RecvMessage rcm) -> rcm msg
            -- We have a suspended computation that want to send a message. This should never happen
            -- because computations are run until they expect input (all output is consumed)
            Left SendMessage{} -> error "Inconsistent state, takeMessagecalled with SendMessage "
            -- See above
            Left Yield{} -> error "Inconsistent state, takeMessagecalled with Yield "
            -- We have a suspended computation that has ended. This should not
            -- happen since finished computations are replaced with returned state
            Left Return{} -> error "Inconsistent state, takeMessagecalled with Yield "
--            Left AskSmpSecret{} -> error $ "Inconsistent state, takeMessagecalled with Yield "
    go [] [] r rs
  where
    go _ys _os r rs = case runMessaging r of
        Left e -> do
            putMVar s rs
            return $ Left e
        -- Right (Left (AskSmpSecret q r'),  ys, os, Nothing, Nothing) -> do
        --     s <- sGen q
        --     go (ys' ++ ys) (os' ++ os) (r' s) rs
        Right (Left (AskSmpSecret _ _),  _, _, _, _) ->
            error "state change before secret"
        Right (rs', ys, os, ss, a) -> do
            putMVar s rs'
            forM_ os sm
            maybe (return ()) oss ss
            maybe (return ()) osmp a
            return $ Right ys


initiator :: CRandom.CPRG g => E2E g ()
initiator = alice

responder :: CRandom.CPRG g => E2E g ()
responder = bob
