{-# LANGUAGE RecordWildCards #-}
module Pontarius.E2E.Session where
import           Control.Applicative((<$>))
import           Control.Concurrent hiding (yield)
import qualified Control.Exception as Ex
import           Control.Monad
import           Control.Monad.Identity (runIdentity)
import           Control.Monad.Reader (runReaderT)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS

import           Pontarius.E2E.Monad
import           Pontarius.E2E.Types
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Message

data E2ESession g = E2ESession { e2eGlobals :: E2EGlobals
                               , e2eState :: MVar (Either (RunState g)
                                                  (E2EState, g))
                               , getSecret :: Maybe BS.ByteString
                                              -> IO BS.ByteString
                               , onSendMessage :: E2EMessage -> IO ()
                               , onStateChange :: MsgState -> IO ()
                               , onSmpAuthChange :: Bool -> IO ()
                               }

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

newSession :: E2E CRandom.SystemRNG () -- ^ alice or bob
           -> E2EGlobals
           -> (Maybe BS.ByteString -> IO BS.ByteString) -- ^ SMP secret producer
           -> (MsgState -> IO ()) -- ^ Message state change notification callback
           -> (Bool -> IO ())  -- ^ SMP authentication state change notification
                               -- callback
           -> (E2EMessage -> IO ())  -- ^ Send message callback
           -> IO (E2ESession CRandom.SystemRNG)
newSession side globals sGen oss osmp sm = do
    g <- CRandom.cprgCreate <$> CRandom.createEntropyPool :: IO CRandom.SystemRNG
    let (st, g') = runIdentity $ runRandT g $ runReaderT  newState globals
    case runMessaging $ runE2E globals st g' side of
        Left e -> error $ "Creating new session produced an error: " ++ show e
        Right (rc, ys, os, ss, a) -> do
           s <- newMVar rc
           forM_ os sm
           -- Should never happen:
           maybe (return ()) oss ss
           maybe (return ()) osmp a
           -----------------------
           return E2ESession{ e2eGlobals      = globals
                            , e2eState        = s
                            , getSecret       = sGen
                            , onSendMessage   = sm
                            , onStateChange   = oss
                            , onSmpAuthChange = osmp
                            }

handleDataMessage :: CRandom.CPRG g => DataMessage -> E2E g ()
handleDataMessage msg = do
    msgPl <- decryptDataMessage msg
    unless (BS.null msgPl) $ yield msgPl

takeMessage :: CRandom.CPRG g
            => E2ESession g
            -> E2EMessage
            -> IO (Either E2EError [BS.ByteString])
takeMessage (E2ESession globals s sGen sm oss osmp) msg =
    Ex.bracketOnError (takeMVar s)
                      (putMVar s) $ \rs -> do
    let r = case rs of
            Right (st, g) -> case msg of
                E2EDataMessage msg' -> runE2E globals st g $ handleDataMessage msg'
                _ -> error "not yet implemented" -- TODO
            Left (RecvMessage rcm) -> rcm msg
            Left SendMessage{} -> error $ "Inconsistent state, takeMessagecalled with SendMessage "
            Left Yield{} -> error $ "Inconsistent state, takeMessagecalled with Yield "
            Left Return{} -> error $ "Inconsistent state, takeMessagecalled with Yield "
--            Left AskSmpSecret{} -> error $ "Inconsistent state, takeMessagecalled with Yield "
    go [] [] r rs
  where
    go ys' os' r rs = case runMessaging r of
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
