{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Main where

import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Monad
import           Data.Default (def)
import           Network
import qualified Network.Xmpp as Xmpp
import           Pontarius.E2E.Serialize (e2eNs)
import           Pontarius.E2E.Xmpp
import           System.Log.Logger


realm    = "species64739.dyndns.org"
username1 = "testuser1"
username2 = "testuser2"
password = "pwd"
resource = Just "bot"

config = def{Xmpp.sessionStreamConfiguration
              = def{Xmpp.connectionDetails =
                         Xmpp.UseHost "localhost" (PortNumber 5222)}}

responder :: IO ()
responder = do
    sem <- newEmptyMVar
    keys <- getKey "keyfile.pem"
    Right sess <- Xmpp.session realm
             (Just (\_ -> [Xmpp.scramSha1 username1 Nothing password]
                     , resource))
             config
    Right c <- Xmpp.listenIQChan Xmpp.Set e2eNs sess
    ctx <- newContext keys [Xmpp.jidQ|testuser2@species64739.dyndns.org/bot|] Responder (return . maybe "abc" id) (putMVar sem) print sess

    forkIO . forever $ do
        ticket <- atomically $ readTChan c
        Xmpp.answerIQ ticket (Right Nothing)
        recvIQ (Xmpp.iqRequestBody ticket) ctx

    forever $ do
        s <- takeMVar sem
        infoM "Pontarius.Xmpp" $ show s
    return ()

initiator = do
    sem <- newEmptyMVar
    keys <- getKey "keyfile2.pem"
    Right sess <- Xmpp.session realm
             (Just (\_ -> [Xmpp.scramSha1 username2 Nothing password]
                     , resource))
             config
    Right c <- Xmpp.listenIQChan Xmpp.Set e2eNs sess
    ctx <- newContext keys [Xmpp.jidQ|testuser1@species64739.dyndns.org/bot|] Initiator (return . maybe "abc" id) (putMVar sem) print sess
    forkIO . forever $ do
        ticket <- atomically $ readTChan c
        Xmpp.answerIQ ticket (Right Nothing)
        recvIQ (Xmpp.iqRequestBody ticket) ctx
    forever $ do
        s <- takeMVar sem
        infoM "Pontarius.Xmpp" $ show s


    return ()




main = do
    updateGlobalLogger "Pontarius.Xmpp" $ setLevel DEBUG
    forkIO responder
    initiator
