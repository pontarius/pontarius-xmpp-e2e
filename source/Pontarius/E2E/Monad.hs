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

import           Control.Monad.Error
import           Control.Monad.Identity
import           Control.Monad.Reader
import           Control.Monad.State.Strict
import           Control.Monad.Trans.State.Strict (liftCatch)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Random.API as CRandom
import qualified Crypto.Random.API as CRandomE2
import qualified Data.ByteString as BS
import           Pontarius.E2E.Types

newtype RandT g m a = RandT { unRandT :: StateT g m a }
                      deriving (Monad, Functor, MonadTrans)

runRandT :: g -> RandT g m a -> m (a, g)
runRandT g m = runStateT (unRandT m) g

class Monad m => MonadRandom g m | m -> g where
    withRandGen :: (g -> (a, g)) -> m a

instance Monad m => MonadRandom g (RandT g m) where
    withRandGen f = RandT . StateT $ return . f

instance (MonadRandom g m, Monad m) => MonadRandom g (ReaderT r m) where
    withRandGen = lift . withRandGen
instance (MonadRandom g m, Monad m) => MonadRandom g (StateT s m) where
    withRandGen = lift . withRandGen

instance (MonadRandom g m, Monad m, Error e) => MonadRandom g (ErrorT e m) where
    withRandGen = lift . withRandGen

instance MonadState s m => MonadState s (RandT g m) where
    get = lift get
    put = lift . put

instance MonadError e m => MonadError e (RandT g m) where
    throwError = lift . throwError
    catchError m f = RandT $ liftCatch catchError (unRandT m) (unRandT . f)

getBytes :: (CRandom.CPRG g, MonadRandom g m) => Int -> m BS.ByteString
getBytes b = withRandGen $ CRandom.genRandomBytes b

data Parameters = Parameters

type E2E g a = ErrorT E2EError (ReaderT E2EGlobals
                                     (StateT E2EState
                                      (RandT g
                                        Messaging )))
                                      a

data E2EMessage = E2EMessage

data Messaging a = SendMessage E2EMessage (Messaging a)
                 | RecvMessage (E2EMessage -> Messaging a)
                 | Yield BS.ByteString (Messaging a)
                 | AskSmpSecret (Maybe BS.ByteString)
                                (BS.ByteString -> Messaging a)
                 | Log String (Messaging a)
                 | Return a
                 deriving Functor


instance Monad Messaging  where
    return = Return
    Return a >>= f = f a
    SendMessage msg g >>= f = SendMessage msg (g >>= f)
    Yield pl f >>= g = Yield pl (f >>= g)
    RecvMessage g >>= f = RecvMessage (\msg -> g msg >>= f)
    AskSmpSecret q g >>= f = AskSmpSecret q (g  >=> f)
