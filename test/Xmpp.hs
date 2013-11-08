{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Main where

import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Concurrent.STM
import           Control.Monad
import           Control.Monad.Fix
import           Data.Default (def)
import           Network
import qualified Network.Xmpp as Xmpp
import qualified Network.Xmpp.IM as Xmpp
import qualified Network.Xmpp.Internal as Xmpp
import           Network.Xmpp.Lens
import           Pontarius.E2E
import           Pontarius.E2E.Serialize (e2eNs)
import           Pontarius.E2E.Types
import           Pontarius.E2E.Xmpp
import           System.IO
import           System.Log.Logger

realm    = "species64739.dyndns.org"
username1 = "testuser1"
username2 = "testuser2"
password = "pwd"
resource = Just "bot"

config :: Xmpp.SessionConfiguration
config = set (streamConfigurationL . connectionDetailsL)
             (Xmpp.UseHost "localhost" (PortNumber 5222)) def

policy _ = return $ Just True

(#) = flip id



thread1 :: IO ()
thread1 = do
    sem <- newEmptyMVar
    keys <- getKey "keyfile.pem"
    let globals = E2EG e2eDefaultParameters keys
    (ctx, plugin) <- e2eInit globals policy (\_ -> return "abc")
    Right sess <- Xmpp.session realm
                 (Just (\_ -> [Xmpp.scramSha1 username1 Nothing password]
                         , resource)) config{Xmpp.plugins = [plugin]}
    forkIO . forever $ do
        m <- Xmpp.pullMessage sess
        infoM "Pontarius.Xmpp.E2E" $ "received message: " ++ show m
        hFlush stdout

    forever $ threadDelay 1000000
    return ()

thread2 :: IO ()
thread2 = do
    sem <- newEmptyMVar
    keys <- getKey "keyfile2.pem"
    let globals = E2EG e2eDefaultParameters keys
    sem <- newEmptyTMVarIO
    (ctx, plugin) <- e2eInit globals policy (\_ -> return "abc")
    Right sess <- Xmpp.session realm
             (Just (\_ -> [Xmpp.scramSha1 username2 Nothing password]
                     , resource)) config{Xmpp.plugins = [plugin]}
    let peer = [Xmpp.jidQ|testuser1@species64739.dyndns.org/bot|]
    startE2E peer ctx (atomically . putTMVar sem)
    atomically (takeTMVar sem) >>= print
    Xmpp.sendMessage (Xmpp.simpleIM peer "Hello encrypted") sess
    infoM "Pontarius.Xmpp.E2E" "sent"
    return ()

main = do
    updateGlobalLogger "Pontarius.Xmpp" $ setLevel DEBUG
    forkIO thread1
    thread2
    threadDelay $ 5*10^6
