{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Control.Applicative ((<$>))
import           Control.Arrow (first, second)
import qualified Crypto.Random as CRandom
import qualified Crypto.Types.PubKey.DSA as DSA
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import qualified Data.ByteString.Lazy as BSL
import           Data.PEM
import           Pontarius.E2E
import           Pontarius.E2E.Types
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Serialize
import Debug.Trace

getKey keyFile = do
    Right ((PEM pName _ bs) : _) <- pemParseLBS `fmap` (BSL.readFile keyFile)
    let Right keysASN1 = decodeASN1 DER (BSL.fromChunks [bs])
    let Right (keyPair ::DSA.KeyPair,  _) = fromASN1 keysASN1
    return keyPair

smpSecret = "abc"

addMessage f (ys, ake, smp, log, ret) = (f ys, ake, smp, log, ret)
stateChange f (ys, ake, smp, log, ret) = (ys, f ake, smp, log, ret)
smpA f (ys, ake, smp, log, ret) = (ys, ake, f smp, log, ret)
addLog f (ys, ake, smp, log, ret) = (ys, ake, smp, f log, ret)

mor x Nothing = Just x
mor _x (Just y) = Just y


braidMessaging (SendMessage msg f) (RecvMessage g) = braidMessaging f (g msg)
braidMessaging (RecvMessage f) (SendMessage msg g) = braidMessaging (f msg) g
braidMessaging (Yield bs f) r = addMessage (first (bs:)) <$> braidMessaging f r
braidMessaging l (Yield bs f) = addMessage (second (bs:)) <$> braidMessaging l f
braidMessaging (AskSmpSecret _ f) r = braidMessaging (f smpSecret) r
braidMessaging l (AskSmpSecret _ f) = braidMessaging l (f smpSecret)
braidMessaging (StateChange st f) r = stateChange (first $ mor st)
                                              <$> braidMessaging f r
braidMessaging l (StateChange st f) = stateChange (second $ mor st)
                                        <$> braidMessaging l f
braidMessaging (SmpAuthenticated s f) r = smpA (first $ mor s)
                                        <$> braidMessaging f r
braidMessaging l (SmpAuthenticated s f) = smpA (second $ mor s)
                                        <$> braidMessaging l f
braidMessaging (Log lm f) r = addLog (first (lm:)) <$> braidMessaging f r
braidMessaging l (Log lm f) = addLog (second (lm:)) <$> braidMessaging l f
braidMessaging (Return a) (Return b) = Right ( ([], [])            -- Yield
                                            , (Nothing , Nothing) -- AKE state
                                            , (Nothing, Nothing) -- SMP state
                                            , ([], []) -- Log
                                            , (a,b)
                                            )
braidMessaging l r = Left (show l ++ " / " ++
                           show r
                           )


main = do
    gl <- CRandom.cprgCreate <$> CRandom.createEntropyPool :: IO CRandom.SystemRNG
    gr <- CRandom.cprgCreate <$> CRandom.createEntropyPool :: IO CRandom.SystemRNG
    kp <- getKey "keyfile.pem"
    let keyPair = (DSA.toPublicKey kp , DSA.toPrivateKey kp)
    let r1 = fst . fst <$> withNewState (E2EG e2eDefaultParameters keyPair) gl alice
    let r2 = fst . fst <$> withNewState (E2EG e2eDefaultParameters keyPair) gr bob
    case braidMessaging r1 r2  of
        Left e -> putStrLn e
        Right r -> print r
    return ()
