{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE RecordWildCards #-}
module Pontarius.E2E where
import           Control.Applicative ((<$>))
import           Control.Monad.Error
import           Control.Monad.Reader
import           Control.Monad.State
import qualified Crypto.MAC.HMAC as HMAC
import           Crypto.Number.ModArithmetic as Mod
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Random.API as CRandom
import           Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Builder as BSB
import           Data.Byteable (constEqBytes)
import           Data.Foldable (foldMap)
import           Data.Monoid (mappend)
import           Pontarius.E2E.Monad
import           Pontarius.E2E.Serialize
import           Pontarius.E2E.Types

(=~=) :: BS.ByteString -> BS.ByteString -> Bool
(=~=) = constEqBytes

encCtrZero key pl = do
    E2EParameters{..} <- asks parameters
    let zeroIV = BS.replicate encryptionBlockSize 0
    return $ encryptionCtr zeroIV  key pl

decCtrZero = encCtrZero


hash pl = do
    E2EParameters {..} <- asks parameters
    return $ paramHash pl

mac key pl = do
    mac <- asks $ paramMac . parameters
    return $ mac key pl

mkKey = do
    E2EParameters {..} <- asks parameters
    getBytes encryptionBlockSize

putAuthState as = modify $ \s -> s{authState = as }
putMsgState ms = modify $ \s -> s{msgState = ms }

makeDHSharedSecret :: Integer -> Integer -> E2E g Integer
makeDHSharedSecret private public = do
    prime <- asks $ dhPrime . parameters
    return $ Mod.exponantiation_rtl_binary public private prime

parameter = asks . (. parameters)

doHash pl = do
    h <- parameter paramHash
    return $ h pl

-- sign :: CRandom.CPRG g => BS.ByteString -> E2E g DSA.Signature
sign x = do
   (_, privKey) <- asks dsaKeyPair
   r <- withRandGen $ \g -> DSA.sign g privKey id x
   return r

-- keyDerivs :: Integer -> KeyDerivatives
keyDerivs s = do
    h <-  parameter paramHash
    let secBytes = BS.pack . unrollInteger $ s
        h2 b = h $ BS.singleton b `BS.append` secBytes
        kdSsid = BS.take 8 $ h2 0x00
        kdC   = h2 0x00
        kdC'  = h2 0x01
        kdM1  = h2 0x03
        kdM2  = h2 0x04
        kdM1' = h2 0x05
        kdM2' = h2 0x06
    return KD{..}

bob1 = do
    r <- mkKey
    gx <- gets $ pub . ourCurrentKey
    let gxBS = encodeInteger gx
    gxBSEnc <- encCtrZero r gxBS
    gxBSHash <- doHash gxBS
    putAuthState $ AuthStateAwaitingDHKey r
    -- return DHC{..}
    return ()

alice1 otrcm = do
    aState <- gets authState
    case aState of
        AuthStateNone -> return ()
        _             -> throwError WrongState
    putAuthState $ AuthStateAwaitingRevealsig otrcm
    gy <- gets $ pub . ourCurrentKey
    return $ DHK gy


bob2 (DHK gyMpi) = do
    aState <- gets authState
    r <- case aState of
        AuthStateAwaitingDHKey r -> return r
        _ -> throwError WrongState
    checkAndSaveDHKey gyMpi
    sm <- mkAuthMessage KeysRSM
    putAuthState AuthStateAwaitingSig
    return $! RSM r sm

alice2 (RSM r sm) = do
    aState <- gets authState
    DHC{..} <- case aState of
        AuthStateAwaitingRevealsig dhc -> return dhc
        _ -> throwError WrongState
    gxBS <- encCtrZero r gxEnc -- decrypt
    h <- parameter paramHash
    protocolGuard HashMismatch (h gxBS =~= gxHash)
    let gx = rollInteger . BS.unpack $ gxBS
    checkAndSaveDHKey gx
    checkAndSaveAuthMessage KeysRSM sm
    am <- mkAuthMessage KeysSM
    putAuthState AuthStateNone
    putMsgState MsgStateEncrypted
    return am

bob3 (SM xaEncrypted xaSha256Mac) = do
    aState <- gets authState
    case aState of
        AuthStateAwaitingSig -> return ()
        _ -> throwError WrongState
    checkAndSaveAuthMessage KeysSM (SM xaEncrypted xaSha256Mac)
    putAuthState AuthStateNone
    putMsgState MsgStateEncrypted
    return ()

protocolGuard e p = unless p . throwError $ ProtocolError e

checkAndSaveDHKey key = do
    prime <- parameter dhPrime
    protocolGuard ValueRange (2 <= key && key <= prime - 2)
    modify (\s -> s{theirCurrentKey = Just key})

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

checkAndSaveAuthMessage keyType (SM xEncrypted xEncMac) = do
    DHKeyPair gx x <- gets ourCurrentKey
    Just gy <- gets theirCurrentKey
    s <- makeDHSharedSecret x gy
    KD{..} <- keyDerivs s
    let (macKey1, macKey2, cryptKey)  = case keyType of
            KeysRSM -> (kdM1 , kdM2 , kdC )
            KeysSM  -> (kdM1', kdM2', kdC')
    xEncMac' <- mac macKey2 xEncrypted
    protocolGuard MACFailure (xEncMac' =~= xEncMac)
    xDec <- decCtrZero cryptKey xEncrypted
    Just (SD theirPub theirKeyID sig) <- return $ decodeStrict' xDec
    theirM <- m gy gx theirPub macKey1
    -- check that the public key they present is the one we have stored (if any)
    storedPubkey <- gets theirPublicKey
    case storedPubkey of
        Nothing -> return ()
        Just sp -> protocolGuard PubkeyMismatch (sp == theirPub)
    protocolGuard SignatureMismatch $ DSA.verify id theirPub sig theirM
    modify $ \s' -> s'{ theirKeyID = theirKeyID
                      , theirPublicKey = Just theirPub
                      , ssid = Just kdSsid
                      }


m ours theirs pubKey messageAuthKey = do
    let m' = BS.concat . BSL.toChunks . BSB.toLazyByteString $
             foldMap toMPI [ ours , theirs]
             `mappend` encodePubkey pubKey
    mac <- parameter paramMac
    return $ mac messageAuthKey m'
  where
    toMPI i = let bs = unrollInteger i in BSB.word32BE (fromIntegral $ length bs)
                                         `mappend` (BSB.word8 `foldMap` bs)
    encodePubkey (DSA.PublicKey (DSA.Params p g q) y) =
        foldMap toMPI [p, q, g, y]


xs pub kid sig aesKey macKey = do
    let sd = SD{ sdPub   = pub
               , sdKeyID = kid
               , sdSig   = sig
               }
    let x = BS.concat . BSL.toChunks $ encode sd
    xEncrypted <- encCtrZero aesKey x
    xMac <- mac macKey xEncrypted
    return (xEncrypted, xMac)
