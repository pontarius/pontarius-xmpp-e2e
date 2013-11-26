{-# LANGUAGE TupleSections #-}
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
import           Control.Monad.Error
import           Control.Monad.Identity (runIdentity)
import           Control.Monad.Reader (runReaderT)
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import           Data.Maybe (listToMaybe)

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
                               , getKey :: Fingerprint -> IO (Maybe Pubkey)
                               }

-- | Run a computation, accumulating all output until it expects more input or
-- the computation is done
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
    go ys os s a gp@(GetPubkey{}) = Right (Left gp , ys [], os [], s, a)
    go ys os s a as@(AskSmpSecret{}) = Right (Left as , ys [], os [], s, a)
    go ys os _s a (StateChange st f) = go ys os (Just st) a f
    go ys os s _a (SmpAuthenticated auth f) = go ys os s (Just auth) f

newSession :: E2EGlobals
           -> (Maybe BS.ByteString -> IO BS.ByteString)
           -> (MsgState -> IO ())
           -> (Bool -> IO ())
           -> (E2EMessage -> IO ())
           -> (Fingerprint -> IO (Maybe Pubkey))
           -> IO (E2ESession CRandom.SystemRNG)
newSession globals sGen oss osmp sm gk = do
    g <- CRandom.cprgCreate <$> CRandom.createEntropyPool :: IO CRandom.SystemRNG
    let (st, g') = runIdentity $ runRandT g $ runReaderT  newState globals
    s <- newMVar $ Right (st, g')
    return E2ESession{ e2eGlobals      = globals
                     , e2eState        = s
                     , getSecret       = sGen
                     , onSendMessage   = sm
                     , onStateChange   = oss
                     , onSmpAuthChange = osmp
                     , getKey          = gk
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


takeAkeMessage :: CRandom.CPRG g =>
                  E2ESession g
                  -> E2EAkeMessage
                  -> IO (Either E2EError (Maybe E2EAkeMessage))
takeAkeMessage sess msg  = do
    res <- takeMessage sess $ E2EAkeMessage msg
    case fst <$> res of
        Left e -> return $ Left e
        Right (_,_:_)   -> error "AKE yielded payload"
        Right (_:_,_:_) -> error "Too many response messages"
        Right ([], _)   -> return $ Right Nothing
        Right ([E2EAkeMessage m], _)   -> return . Right $ Just m
        Right ([_], _)   -> error "AKE tried to send non-AKE message"

takeDataMessage :: CRandom.CPRG g =>
                   E2ESession g
                   -> DataMessage
                   -> IO (Either E2EError (BS.ByteString, BS.ByteString))
takeDataMessage sess msg = do
    res <- takeMessage sess $ E2EDataMessage msg
    case res of
        Left e -> return $ Left e
        Right ((_:_, _:_    ), _      ) -> error "decrypt yielded response message"
        Right (([] , []     ), _      ) -> error "Data message didn't yield"
        Right (([] , (_:_:_)), _      ) -> error "Too many yields"
        Right ((_  , _      ), Nothing) -> error "No ssid saved"
        Right (([] , [y]    ), Just s ) -> return $ Right (y, s)

takeMessage :: CRandom.CPRG g
            => E2ESession g
            -> E2EMessage
            -> IO (Either E2EError ( ( [E2EMessage]
                                     , [BS.ByteString])
                                   , Maybe BS.ByteString))
takeMessage (E2ESession globals s _sGen sm oss osmp gpk) msg =
    Ex.bracketOnError (takeMVar s)
                      (putMVar s) $ \rs -> do
    let r = case rs of
            -- There's no suspended computation, so we can start a new one
            Right (st, g) -> case msg of
                E2EDataMessage msg' -> runE2E globals st g
                                         $ handleDataMessage msg'
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
            Left s -> error $ "unexpected state: " ++ show (void s)
--            Left AskSmpSecret{} -> error $ "Inconsistent state, takeMessagecalled with Yield "
    let s = either (const Nothing) (ssid . fst) rs
    fmap (, s) <$> go [] [] r rs
  where
    go ys os r rs = case runMessaging r of
        Left e -> do
            putMVar s rs
            return $ Left e
        -- Right (Left (AskSmpSecret q r'),  ys, os, Nothing, Nothing) -> do
        --     s <- sGen q
        --     go (ys' ++ ys) (os' ++ os) (r' s) rs
        Right (Left (AskSmpSecret _ _),  _, _, _, _) ->
            error "state change before secret"
        Right (rs'@(Left (GetPubkey fp g)), ys', os', ss, a)  -> do
                mbpk <- gpk fp
                case mbpk of
                    Just pk -> go (ys ++ ys') (os ++ os') (g pk) rs'
                    Nothing -> do
                        putMVar s rs'
                        return $ Left NoPubkey
        Right (rs', ys, os@(_:_:_), ss, a) -> error $
                                              "Too many answer messages"
                                              ++ show os
        Right (rs', ys', os', ss, a) -> do
            putMVar s rs'
            forM_ (os ++ os') sm
            maybe (return ()) oss ss
            maybe (return ()) osmp a
            return $ Right (os++os',ys++ys')


initiator :: CRandom.CPRG g => E2E g ()
initiator = alice

responder :: CRandom.CPRG g => E2E g ()
responder = bob
