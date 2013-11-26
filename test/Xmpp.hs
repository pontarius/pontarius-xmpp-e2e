{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Main where

import           Control.Applicative ((<$>))
import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Concurrent.STM
import           Control.Monad
import           Control.Monad.Fix
import qualified Crypto.Types.PubKey.DSA as DSA
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
import qualified Data.Map as Map
import qualified Data.ByteString as BS

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

type Keystore = Map.Map (KeyType, BS.ByteString) DSA.PublicKey

makeKeystore = do
    keys <- mapM getKey ["keyfile2.pem", "keyfile.pem", "keyfile4096-1.pem"]
    return $ Map.fromList [ (( KeyTypeDSA
                             , pubkeyFingerprint e2eDefaultParameters k), k)
                          | k <- fst <$> keys ]

thread1 :: Keystore -> IO ()
thread1 store = do
    sem <- newEmptyMVar
    keys <- getKey "keyfile4096-1.pem"
    let globals = E2EG e2eDefaultParameters keys
    (ctx, plugin) <- e2eInit globals policy (\_ -> return "abc")
                     ( return . flip Map.lookup store )
    Right sess <- Xmpp.session realm
                 (Just (\_ -> [Xmpp.scramSha1 username1 Nothing password]
                         , resource)) config{Xmpp.plugins = [plugin]}
    forkIO . forever $ do
        Right m <- Xmpp.pullMessage sess
        infoM "Pontarius.Xmpp.E2E" $ "received message: " ++ show m
        infoM "Pontarius.Xmpp.E2E" $ "Message was : " ++ (if wasEncrypted m then "" else "not " ) ++ "encrypted."
        hFlush stdout

    forever $ threadDelay 1000000
    return ()

thread2 :: Keystore -> IO ()
thread2 store = do
    sem <- newEmptyMVar
    keys <- getKey "keyfile2.pem"
    theirPubkey <- fst <$> getKey "keyfile4096-1.pem"
    let globals = E2EG e2eDefaultParameters keys
    sem <- newEmptyTMVarIO
    (ctx, plugin) <- e2eInit globals policy (\_ -> return "abc")
                     ( return . flip Map.lookup store )
    Right sess <- Xmpp.session realm
             (Just (\_ -> [Xmpp.scramSha1 username2 Nothing password]
                     , resource)) config{Xmpp.plugins = [plugin]}
    let peer = [Xmpp.jidQ|testuser1@species64739.dyndns.org/bot|]
    Xmpp.sendMessage (Xmpp.simpleIM peer "Unencrypted") sess
    startE2E peer ctx (atomically . putTMVar sem)
    atomically (takeTMVar sem) >>= print
    Xmpp.sendMessage (Xmpp.simpleIM peer "Hello encrypted") sess
    infoM "Pontarius.Xmpp.E2E" "sent"
    return ()

main = do
    store <- makeKeystore
    updateGlobalLogger "Pontarius.Xmpp" $ setLevel INFO
    forkIO $ thread1 store
    thread2 store
    threadDelay $ 5*10^6
