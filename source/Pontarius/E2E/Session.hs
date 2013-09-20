module Pontarius.E2E.Session where

data OtrSession g = OtrSession { otrDSAKeys :: (DSA.PublicKey, DSA.PrivateKey)
                               , otrState :: MVar (Either (RunState g)
                                                  (OtrState, g))
                               , getSecret :: Maybe BS.ByteString
                                              -> IO BS.ByteString
                               , onSendMessage :: OtrMessage -> IO ()
                               , onStateChange :: MsgState -> IO ()
                               , onSmpAuthChange :: Bool -> IO ()
                               }

newSession side keys sGen oss osmp sm = do
    g <- CRandom.cprgCreate <$> CRandom.createEntropyPool :: IO CRandom.SystemRNG
    let (st, g') = runRand g newState
    case runMessaging $ runOtrT keys st side g' of
        Left e -> error "Creating new session produced an error"
        Right (rc, ys, os, ss, a) -> do
           s <- newMVar rc
           forM_ os sm
           -- Should never happen:
           maybe (return ()) oss ss
           maybe (return ()) osmp a
           -----------------------
           return OtrSession{ otrDSAKeys      = keys
                            , otrState        = s
                            , getSecret       = sGen
                            , onSendMessage   = sm
                            , onStateChange   = oss
                            , onSmpAuthChange = osmp
                            }
