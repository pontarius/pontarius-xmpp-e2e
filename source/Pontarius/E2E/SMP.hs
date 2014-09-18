{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -fno-warn-name-shadowing #-} -- TODO: clean up name shadowing

{-# OPTIONS_GHC -fno-warn-unused-matches #-} -- @NOCOMMIT

module Pontarius.E2E.SMP where

import           Control.Monad.Except
import           Control.Monad.Free
import           Control.Monad.Reader
import           Control.Monad.State
import qualified Crypto.Hash.SHA256 as SHA256
import           Crypto.Number.ModArithmetic as Mod
import qualified Crypto.Random as CRandom
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Serialize as Serialize
import           Data.Text (Text)
import qualified Data.Text.Encoding as Text
import           Data.Word

import           Pontarius.E2E.Monad
import           Pontarius.E2E.Types
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Serialize

smpHash :: Word8 -> Integer -> Maybe Integer -> Integer
smpHash v b1 b2 = rollInteger . BS.unpack . SHA256.hash . Serialize.runPut $ do
        Serialize.putWord8 v
        putMPI b1
        case b2 of
            Nothing -> return ()
            Just b2' -> putMPI b2'

mkSmpExponent :: (CRandom.CPRG g, MonadRandom g m, Functor m) => m Integer
mkSmpExponent = randomIntegerBytes 192

mkSecret :: (MonadReader E2EGlobals m, MonadState E2EState m) =>
            ((PubKey, PubKey) -> (PubKey, PubKey)) -> ByteString -> m Integer
mkSecret perm uSecret = do
    ourKey <- asks pubKey
    Just theirKey <- gets theirPubKey
    Just s <- gets ssid
    let (iKey, rKey) = perm (ourKey, theirKey)
        sBytes = Serialize.runPut $ do
            Serialize.putWord8 0x01
            Serialize.putByteString $ fingerPrint iKey
            Serialize.putByteString $ fingerPrint rKey
            Serialize.putByteString s
            Serialize.putByteString uSecret
    return . rollInteger . BS.unpack $ SHA256.hash sBytes
  where
    fingerPrint = SHA256.hash . encodePubkey

getQ :: MonadReader E2EGlobals m => m Integer
getQ = do
    p <- prime
    return $ (p - 1) `div` 2

sendSmpMessage :: SmpMessage -> SMP ()
sendSmpMessage msg = lift . lift . lift $ Free (SendSmpMessage msg (return ()))

recvSmpMessage :: Int -> SMP SmpMessage
recvSmpMessage tp = lift . lift . lift $ Free (RecvSmpMessage tp return)


rangeGuard :: (MonadError E2EError m, MonadReader E2EGlobals m) =>
              String -> Integer -> m ()
rangeGuard name x = do
    p <- prime
    protocolGuard ValueRange name $ 2 <= x && x <= (p - 2)

hashGuard :: MonadError E2EError m =>
             String -> Integer -> Word8 -> Integer -> Maybe Integer -> m ()
hashGuard name l b r1 r2 =
    protocolGuard HashMismatch name $ l == smpHash b r1 r2

-- smp1 :: CRandom.CPRG g => Integer -> Smp g Bool
smp1 :: Maybe Text
     -> Text
     -> (Integer,
         Integer,
         Integer,
         Integer,
         Integer,
         Integer,
         Integer,
         Integer)
     -> SMP Bool
smp1 mbQuestion x' (a2, a3, r2, r3, r4, r5, r6, r7) = do
    p <- prime
    q <- getQ
    x <- mkSecret id (Text.encodeUtf8 x')
    let infixr 8 ^.
        b ^. e = Mod.exponantiation_rtl_binary b e p
        infixr 7 *.
        l *. r = (l * r) `mod` p
        infixl 7 /.
        l /. r = case inverse r p of
            Nothing -> error $ "could not invert " ++ show r
            Just r' -> l *. r'
    -- [a2, a3, r2, r3] <- replicateM 4 mkSmpExponent
    let g2a = 2 ^. a2
        g3a = 2 ^. a3
        c2  = smpHash 1 (2 ^. r2) Nothing
        d2  = (r2 - a2*c2) `mod` q
        c3  = smpHash 2 (2 ^. r3) Nothing
        d3  = (r3 - a3*c3) `mod` q
    sendSmpMessage $ SmpMessage1 mbQuestion g2a c2 d2 g3a c3 d3
    ----------------------------------------------------------------------------
    SmpMessage2 g2b' c2' d2' g3b' c3' d3' pb' qb' cp' d5' d6' <- recvSmpMessage 2
    rangeGuard "alice g2b" g2b'
    rangeGuard "alice g3b" g3b'
    rangeGuard "alice pb"  pb'
    rangeGuard "alice qb"  qb'
    let g3 = g3b' ^. a3
    hashGuard "alice c2" c2'   3 (2 ^. d2' *. g2b' ^. c2') Nothing
    hashGuard "alice c3" c3'   4 (2 ^. d3' *. g3b' ^. c3') Nothing
    -- TODO: fix and reinstate
    -- hashGuard "alice cp" cp'   5 (g3 ^. d5' *. pb' ^. cp')
    --                              (Just $ 2 ^. d5' *. d2' ^. d6' *. qb' ^. cp')
    -- [r4, r5, r6, r7] <- replicateM 4 mkSmpExponent
    let g2 = g2b' ^. a2
        pa = g3 ^. r4
        qa = 2 ^. r4 *. g2 ^. x
        cp = smpHash 6 (g3 ^. r5) $ Just (2 ^. r5 *. g2 ^. r6)
        d5 = (r5 - r4 * cp') `mod` q
        d6 = (r6 - x  * cp') `mod` q
        ra = (qa /. qb') ^. a3
        cr = smpHash 7 (2 ^. r7) (Just $ (qa /. qb') ^. r7)
        d7 = (r7 - a3 * cr) `mod` q
    sendSmpMessage $ SmpMessage3 pa qa cp d5 d6 ra cr d7
    -------------------------------------------------
    SmpMessage4 rb' cr' d7' <- recvSmpMessage 4
    rangeGuard "alice rb" rb'
    -- TODO: fix and reinstate
    -- hashGuard "alice cr" cr'   8 (2 ^. d7' *. g3b' ^. cr')
    --                              (Just $ (qa /. qb') ^. d7 *. rb' ^. cr')
    return $! (pa /. pb') == rb' ^. a3

smp2 :: Text
     -> (Integer,
         Integer,
         Integer,
         Integer,
         Integer,
         Integer,
         Integer,
         Integer)
     -> SmpMessage
     -> SMP Bool
smp2 y' (b2, b3, r2, r3, r4, r5, r6, r7) msg1 = do
    p <- prime
    q <- getQ
    y <- mkSecret (\(x,y) -> (y,x)) (Text.encodeUtf8 y')
    let infixr 8 ^.
        b ^. e = Mod.exponantiation_rtl_binary b e p
        infixr 7 *.
        x *. y = mulmod x y p
        mulmod x' y' p = (x' * y') `mod` p
        infixl 7 /.
        x /. y = case inverse y p of
            Nothing -> error $ "could not invert " ++ show y
            Just y' -> x *. y'
    let SmpMessage1 _ g2a' c2' d2' g3a' c3' d3' = msg1
    rangeGuard "bob g2a'" g2a'
    rangeGuard "bob gaa'" g3a'
    hashGuard "bob c2'" c2' 1 (2 ^. d2' *. g2a' ^. c2') Nothing
    hashGuard "bob c3'" c3' 2 (2 ^. d3' *. g3a' ^. c3') Nothing
    -- [b2, b3, r2, r3, r4, r5, r6] <- replicateM 7 mkSmpExponent
    let g2b = 2 ^. b2
        g3b = 2 ^. b3
        c2 = smpHash 3 (2 ^. r2) Nothing
        d2 = (r2 - b2 * c2) `mod` q
        c3 = smpHash 4 (2 ^. r3) Nothing
        d3 = (r3 - b3 * c3) `mod` q
        g2 = g2a' ^. b2
        g3 = g3a' ^. b3
        pb = g3 ^. r4
        qb = 2 ^. r4 *. g2 ^. y
        cp = smpHash 5 (g3 ^. r5) (Just $ (2 ^. r5 *. g2 ^. r6))
        d5 = (r5 - r4 * cp) `mod` q
        d6 = (r6 - y  * cp) `mod` q
    sendSmpMessage $ SmpMessage2 g2b c2 d2 g3b c3 d3 pb qb cp d5 d6
    ---------------------------------------------------------------
    SmpMessage3 pa' qa' cp' d5' d6' ra' cr' d7' <- recvSmpMessage 3
    rangeGuard "bob pa'" pa'
    rangeGuard "bob qa'" qa'
    rangeGuard "bob ra'" ra'
    -- TODO: fix and reinstate
    -- hashGuard "bob cp" cp' 6 (g3 ^. d5' *. pa' ^. cp')
    --     (Just $  2 ^. d5' *. g2 ^. d6' *. qa' ^. cp')
    -- TODO: fix and reinstate
    -- hashGuard "bob cr" cr' 7 (2 ^. d7' *. g3a' ^. cr' )
    --     (Just $ (qa' /. qb) ^. d7' *. ra' ^. cr' )
--    r7 <- mkSmpExponent
    let rb = (qa' /. qb) ^. b3
        cr = smpHash 8 (2 ^. r7) (Just $ (qa' /. qb) ^. r7)
        d7 = (r7 - b3 * cr) `mod` q
    hashGuard "bob cr" cr  8 (2 ^. d7 *. g3b ^. cr)
                                 (Just $ (qa' /. qb) ^. d7 *. rb ^. cr)
    sendSmpMessage $ SmpMessage4 rb cr d7
    ------------------------
    let rab = ra' ^. b3
    return $! (pa' /. pb) == rab
