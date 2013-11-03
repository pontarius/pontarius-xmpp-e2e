{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Main where

import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Concurrent.STM
import           Control.Monad
import           Data.Default (def)
import           Network
import qualified Network.Xmpp as Xmpp
import qualified Network.Xmpp.Internal as Xmpp
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

config = def{Xmpp.sessionStreamConfiguration
              = def{Xmpp.connectionDetails =
                         Xmpp.UseHost "localhost" (PortNumber 5222)}}

thread1 :: IO ()
thread1 = do
    sem <- newEmptyMVar
    keys <- getKey "keyfile.pem"
    let globals = E2EG e2eDefaultParameters keys
    cfg <- e2eInit globals (\_ -> return "abc")
    Right sess <- Xmpp.session realm
             (Just (\_ -> [Xmpp.scramSha1 username1 Nothing password]
                     , resource))
             config{ Xmpp.extraStanzaHandlers = [handleE2E (\_ -> return $ Just True) cfg] }
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
    cfg <- e2eInit globals (\_ -> return "abc")
    sem <- newEmptyTMVarIO
    Right sess <- Xmpp.session realm
             (Just (\_ -> [Xmpp.scramSha1 username2 Nothing password]
                     , resource))
             config{ Xmpp.extraStanzaHandlers = [handleE2E (\_ -> return $ Just True) cfg] }
    let peer = [Xmpp.jidQ|testuser1@species64739.dyndns.org/bot|]
    startE2E peer cfg (atomically . putTMVar sem)  sess
    atomically (takeTMVar sem) >>= print
    sendE2EMsg cfg peer (Xmpp.MessageS Xmpp.message{ Xmpp.messageTo = Just peer}) sess
    infoM "Pontarius.Xmpp.E2E" "sent"
    return ()

main = do
    updateGlobalLogger "Pontarius.Xmpp" $ setLevel DEBUG
    forkIO thread1
    thread2
    threadDelay $ 5*10^6
