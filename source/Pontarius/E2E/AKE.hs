{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleContexts #-}
module Pontarius.E2E.AKE where
import           Control.Applicative ((<$>))
import           Control.Monad.Error
import           Control.Monad.Reader
import           Control.Monad.State
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Random as CRandom
import           Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Builder as BSB
import           Data.Foldable (foldMap)
import           Data.Monoid (mappend)
import           Pontarius.E2E.Helpers
import           Pontarius.E2E.Monad
import           Pontarius.E2E.Serialize
import           Pontarius.E2E.Types

-------------------------------------
-- The high level protocol ----------
-------------------------------------

alice1 :: CRandom.CPRG g => E2E g DHCommitMessage
alice1 = do
    r <- mkKey
    gx <- gets $ pub . ourCurrentKey
    let gxBS = encodeInteger gx
    gxBSEnc <- encCtrZero r gxBS
    gxBSHash <- doHash gxBS
    putAuthState $ AuthStateAwaitingDHKey r
    return DHC{ gxBSEnc = gxBSEnc
              , gxBSHash = gxBSHash
              }


bob1 :: DHCommitMessage -> E2E g DHKeyMessage
bob1 otrcm = do
    aState <- gets authState
    case aState of
        AuthStateNone -> return ()
        _             -> throwError WrongState
    putAuthState $ AuthStateAwaitingRevealsig otrcm
    gy <- gets $ pub . ourCurrentKey
    return $ DHK gy


alice2 :: CRandom.CPRG g => DHKeyMessage -> E2E g RevealSignatureMessage
alice2 (DHK gyMpi) = do
    aState <- gets authState
    r <- case aState of
        AuthStateAwaitingDHKey r -> return r
        _ -> throwError WrongState
    checkAndSaveDHKey gyMpi
    sm <- mkAuthMessage KeysRSM
    putAuthState AuthStateAwaitingSig
    return $! RSM r sm


bob2 :: CRandom.CPRG g => RevealSignatureMessage -> E2E g SignatureMessage
bob2 (RSM r sm) = do
    aState <- gets authState
    DHC{ gxBSEnc = gxBSEnc
       , gxBSHash = gxBSHash
       } <- case aState of
        AuthStateAwaitingRevealsig dhc -> return dhc
        _ -> throwError WrongState
    gxBS <- decCtrZero r gxBSEnc
    gxBSHash' <- hash gxBS
    protocolGuard HashMismatch "bob2 hash" (gxBSHash' =~= gxBSHash)
    let gx = rollInteger . BS.unpack $ gxBS
    checkAndSaveDHKey gx
    checkAndSaveAuthMessage KeysRSM sm
    am <- mkAuthMessage KeysSM
    putAuthState AuthStateNone
    putMsgState MsgStateEncrypted
    return am

alice3 :: SignatureMessage -> E2E g ()
alice3 (SM xaEncrypted xaSha256Mac) = do
    aState <- gets authState
    case aState of
        AuthStateAwaitingSig -> return ()
        _ -> throwError WrongState
    checkAndSaveAuthMessage KeysSM (SM xaEncrypted xaSha256Mac)
    putAuthState AuthStateNone
    putMsgState MsgStateEncrypted
    return ()

--------------------------------

-- TODO: check for message types
bob :: CRandom.CPRG g => E2E g ()
bob = do
    E2EAkeMessage (DHCommitMessage msg1) <- recvMessage
    sendMessage =<< E2EAkeMessage . DHKeyMessage <$> bob1 msg1
    E2EAkeMessage (RevealSignatureMessage msg2) <- recvMessage
    sendMessage =<< E2EAkeMessage . SignatureMessage <$> bob2 msg2

alice :: CRandom.CPRG g => E2E g ()
alice = do
    sendMessage =<< E2EAkeMessage . DHCommitMessage <$> alice1
    E2EAkeMessage (DHKeyMessage msg1) <- recvMessage
    sendMessage =<< E2EAkeMessage . RevealSignatureMessage <$> alice2 msg1
    E2EAkeMessage (SignatureMessage msg2) <- recvMessage
    alice3 msg2

---------------------
-- helpers ----------
---------------------
checkAndSaveDHKey :: (MonadState E2EState m, MonadReader E2EGlobals m,
                      MonadError E2EError m) =>
                     Integer -> m ()
checkAndSaveDHKey key = do
    p <- prime
    protocolGuard ValueRange "DH" (2 <= key && key <= p - 2)
    modify (\s -> s{theirCurrentKey = Just key})

keyDerivs :: Integer -> E2E g KeyDerivatives
keyDerivs s = do
    h <-  parameter paramHash
    let secBytes = encodeInteger $ s
        h2 b = h $ BS.singleton b `BS.append` secBytes
        kdSsid = BS.take 8 $ h2 0x00
        kdC   = h2 0x00
        kdC'  = h2 0x01
        kdM1  = h2 0x03
        kdM2  = h2 0x04
        kdM1' = h2 0x05
        kdM2' = h2 0x06
    return KD{..}

mkAuthMessage :: CRandom.CPRG g => AuthKeys -> E2E g SignatureMessage
mkAuthMessage keyType = do
    DHKeyPair gx x <- gets ourCurrentKey
    Just gy <- gets theirCurrentKey
    s <- makeDHSharedSecret x gy
    KD{..} <- keyDerivs s
    let (macKey1, macKey2, aesKey)  = case keyType of
            KeysRSM -> (kdM1 , kdM2 , kdC )
            KeysSM  -> (kdM1', kdM2', kdC')
    (ourPub, _) <- asks dsaKeyPair
    keyID <- gets ourKeyID
    mb <- m gx gy ourPub macKey1
    sig <- sign mb
    (xbEncrypted, xbEncMac) <- xs ourPub keyID sig aesKey macKey2
    return $ SM xbEncrypted xbEncMac

checkAndSaveAuthMessage :: AuthKeys -> SignatureMessage -> E2E g ()
checkAndSaveAuthMessage keyType (SM xEncrypted xEncMac) = do
    DHKeyPair gx x <- gets ourCurrentKey
    Just gy <- gets theirCurrentKey
    s <- makeDHSharedSecret x gy
    KD{..} <- keyDerivs s
    let (macKey1, macKey2, cryptKey)  = case keyType of
            KeysRSM -> (kdM1 , kdM2 , kdC )
            KeysSM  -> (kdM1', kdM2', kdC')
    xEncMac' <- mac macKey2 xEncrypted
    protocolGuard MACFailure "auth message" $ (xEncMac' =~= xEncMac)
    xDec <- decCtrZero cryptKey xEncrypted
    Just (SD theirPub theirKeyID sig) <- return $ decodeStrict' xDec
    theirM <- m gy gx theirPub macKey1
    -- check that the public key they present is the one we have stored (if any)
    storedPubkey <- gets theirPublicKey
    case storedPubkey of
        Nothing -> return ()
        Just sp -> protocolGuard PubkeyMismatch "" $ sp == theirPub
    protocolGuard SignatureMismatch "" $ DSA.verify id theirPub sig theirM
    modify $ \s' -> s'{ theirKeyID = theirKeyID
                      , theirPublicKey = Just theirPub
                      , ssid = Just kdSsid
                      }


m :: MonadReader E2EGlobals m
     => Integer
     -> Integer
     -> DSA.PublicKey
     -> BS.ByteString
     -> m BS.ByteString
m ours theirs pubKey messageAuthKey = do
    let m' = BS.concat . BSL.toChunks . BSB.toLazyByteString $
             foldMap toMPIBuilder [ ours , theirs]
             `mappend` encodePubkey pubKey
    mac messageAuthKey m'
  where
    encodePubkey (DSA.PublicKey (DSA.Params p g q) y) =
        foldMap toMPIBuilder [p, q, g, y]


xs :: DSA.PublicKey
   -> Integer
   -> DSA.Signature
   -> BS.ByteString
   -> BS.ByteString
   -> E2E g (BS.ByteString, BS.ByteString)
xs pub kid sig aesKey macKey = do
    let sd = SD{ sdPub   = pub
               , sdKeyID = kid
               , sdSig   = sig
               }
    let x = BS.concat . BSL.toChunks $ encode sd
    xEncrypted <- encCtrZero aesKey x
    xMac <- mac macKey xEncrypted
    return (xEncrypted, xMac)
