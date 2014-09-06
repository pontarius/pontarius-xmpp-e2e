{-# LANGUAGE PackageImports #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
module Pontarius.E2E.Monad where

import                           Control.Applicative
import                           Control.Monad.Except
import                           Control.Monad.Free
import                           Control.Monad.Reader
import                           Control.Monad.State.Strict
import                           Control.Monad.Trans.State.Strict (liftCatch)
import qualified "crypto-random" Crypto.Random as CRandom
import qualified                 Data.ByteString as BS
import                           Pontarius.E2E.Types

newtype RandT g m a = RandT { unRandT :: StateT g m a }
                      deriving (Monad, Functor, MonadTrans, Applicative)

runRandT :: g -> RandT g m a -> m (a, g)
runRandT g m = runStateT (unRandT m) g

runRandTIO :: RandT CRandom.SystemRNG IO b -> IO b
runRandTIO m = do
    g <- CRandom.cprgCreate `fmap` CRandom.createEntropyPool :: IO CRandom.SystemRNG
    fst `fmap` runRandT g m

class Monad m => MonadRandom g m | m -> g where
    withRandGen :: (g -> (a, g)) -> m a

instance Monad m => MonadRandom g (RandT g m) where
    withRandGen f = RandT . StateT $ return . f

instance (MonadRandom g m, Monad m) => MonadRandom g (ReaderT r m) where
    withRandGen = lift . withRandGen
instance (MonadRandom g m, Monad m) => MonadRandom g (StateT s m) where
    withRandGen = lift . withRandGen

instance (MonadRandom g m, Monad m) => MonadRandom g (ExceptT e m) where
    withRandGen = lift . withRandGen

instance MonadState s m => MonadState s (RandT g m) where
    get = lift get
    put = lift . put

instance MonadError e m => MonadError e (RandT g m) where
    throwError = lift . throwError
    catchError m f = RandT $ liftCatch catchError (unRandT m) (unRandT . f)

getBytes :: (CRandom.CPRG g, MonadRandom g m) => Int -> m BS.ByteString
getBytes b = withRandGen $ CRandom.cprgGenerate b

data Parameters = Parameters

type E2E g a = ReaderT E2EGlobals
               (StateT E2EState
               (RandT g
               (ExceptT E2EError
               Messaging )))
               a

runE2E :: E2EGlobals
         -> E2EState
         -> g
         -> E2E g a
         -> Messaging (Either E2EError ((a, E2EState), g))
runE2E globals s0 g = runExceptT
                      . runRandT g
                      . flip runStateT s0
                      . flip runReaderT globals

execE2E :: E2EGlobals
         -> E2EState
         -> g
         -> E2E g a
         -> Messaging (Either E2EError (E2EState, g))
execE2E globals s0 g = runExceptT
                      . (liftM $ \((_, s), g') -> (s,g'))
                      . runRandT g
                      . flip runStateT s0
                      . flip runReaderT globals

liftMessaging :: MessagingF (Free MessagingF a) -> E2E g a
liftMessaging = lift . lift . lift . lift . Free

yield :: BS.ByteString -> E2E g ()
yield s = liftMessaging $ Yield s (return ())

askSecret :: Maybe BS.ByteString -> E2E g BS.ByteString
askSecret q =  liftMessaging $ AskSmpSecret q return

recvMessage :: E2E g E2EMessage
recvMessage = liftMessaging $ RecvMessage return

sendMessage :: E2EMessage -> E2E g ()
sendMessage msg = liftMessaging $ SendMessage msg (return ())

sign :: BS.ByteString -> E2E g BS.ByteString
sign bs = liftMessaging $ Sign bs return

verify :: PubKey -> BS.ByteString -> BS.ByteString -> E2E g ()
verify pkID signature plaintext =
    liftMessaging $ Verify pkID signature plaintext (return ())

stateChange :: MsgState -> E2E g ()
stateChange s = liftMessaging $ StateChange s (return ())
