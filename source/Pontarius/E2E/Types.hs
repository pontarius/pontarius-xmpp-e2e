{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveFunctor #-}
module Pontarius.E2E.Types
where

import           Control.Arrow (first)
import           Control.Concurrent.STM
import qualified Control.Monad.CryptoRandom as CR
import           Control.Monad.Free
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import qualified Data.Map as Map
import           Data.Text (Text)
import           Data.Typeable (Typeable)
import qualified Network.Xmpp as Xmpp

type CTR = BS.ByteString
type MAC = BS.ByteString
type DATA = BS.ByteString
type SSID = BS.ByteString

data DHKeyPair = DHKeyPair { pub  :: !Integer
                           , priv :: !Integer
                           } deriving Show

data MsgState = MsgStatePlaintext
              | MsgStateEncrypted VerifyInfo SSID
              | MsgStateFinished
              deriving (Eq, Show)

data SmpMessagingF r = SendSmpMessage SmpMessage r
                     | RecvSmpMessage Int (SmpMessage -> r)
                     deriving Functor

type SmpMessaging = Free SmpMessagingF

data ProtocolError = MACFailure
                   | ValueRange -- DH key outside [2, prime - 2]
                   | PubkeyMismatch -- Offered DSA pubkey doesn't match the one
                                    -- we have
                   | SignatureMismatch
                   | HashMismatch
                   | DeserializationError String -- couldn deserialize data
                                                 -- structure
                   | UnexpectedMessagetype
                   | WrongKeyID -- KeyID is not current or current + 1
                     deriving (Show, Eq)

data E2EError = WrongState String
              | RandomGenError CR.GenError
              | InstanceTagRange
              | NoPeerDHKey -- theirCurrentKey is Nothing
              | NoPubkey -- We don't know the pubkey with the give fingerprint
              | ProtocolError ProtocolError String -- One of the checks failed
                deriving (Show, Eq, Typeable)

data AuthState = AuthStateNone
               | AuthStateAwaitingDHKey BS.ByteString
               | AuthStateAwaitingRevealsig DHCommitMessage
               | AuthStateAwaitingSig
                 deriving Show

data SmpMessage = SmpMessage1 { question :: Maybe Text
                              , g2a, c2, d2, g3a, c3, d3 :: !Integer }
                | SmpMessage2 {g2b, c2', d2', g3b, c3'
                              , d3' , pb, qb, cp, d5, d6 :: !Integer}
                | SmpMessage3 {pa, qa, cp', d5, d6, ra, cr, d7 :: !Integer}
                | SmpMessage4 {rb, cr, d7' :: !Integer}


                  deriving (Show, Eq)

data SmpState = SmpDone
              | SmpInProgress (SmpMessaging (Either E2EError Bool))
              | SmpGotChallenge (Text -> (SmpMessaging (Either E2EError Bool)))

instance Show SmpState where
    show SmpDone = "SmpDone"
    show SmpInProgress{} = "SmpInProgress"
    show SmpGotChallenge{} = "SmpGotChallenge"

data VerifyInfo = VerifyInfo { keyID :: !BS.ByteString -- Identifier for the key
                                                       -- seen
                             } deriving (Eq, Show)

data E2EState = E2EState { authState        :: !AuthState
                         , msgState         :: !MsgState
                         , theirPubKey      :: !(Maybe PubKey)
                         , ourKeyID         :: !Integer -- KeyID of ourCurrentKey
                         , ourCurrentKey    :: !DHKeyPair
                         , ourPreviousKey   :: !DHKeyPair
                         , mostRecentKey    :: !Integer -- KeyID of the most
                                                       -- recent key that the
                                                       -- other party
                                                       -- acknowledged receiving
                         , nextDH           :: !DHKeyPair
                         , theirKeyID       :: !Integer -- KeyID of the lastest
                                                       -- of their keys we have
                                                       -- on file
                         , theirCurrentKey  :: !(Maybe Integer)
                         , theirPreviousKey :: !(Maybe Integer)
                           -- Instance Tags
                         , counter          :: !Integer
                         , ssid             :: !(Maybe BS.ByteString)
                           -- SMP ------------------------------
                         , smpState         :: !SmpState
                         } deriving Show

data MessagePayload = MP { messagePlaintext :: !BS.ByteString
--                         , tlvs :: ![TLV]
                         } deriving (Eq, Show)

-- data RawDataMessage = RDM { flags :: OtrByte
--                           , senderKeyID :: OtrInt
--                           , recipientKeyID :: OtrInt
--                           , nextDHy :: Integer
--                           , ctrHi :: CTR
--                           , messageAes128 :: DATA
--                           } deriving (Eq, Show)

-- data DataMessage = DM { rawDataMessage :: OtrRawDataMessage
--                       , messageMAC :: MAC
--                       , oldMACKeys  :: DATA
--                       } deriving (Eq, Show)

data KeyDerivatives = KD { kdSsid
                         , kdC
                         , kdC'
                         , kdM1
                         , kdM2
                         , kdM1'
                         , kdM2'
                           :: !BS.ByteString
                         }
                       deriving (Eq, Show)

data MessageKeys = MK { sendEncKey
                      , sendMacKey
                      , recvEncKey
                      , recvMacKey :: !BS.ByteString
                      } deriving Show

data DHCommitMessage = DHC{ gxBSEnc  :: !DATA
                          , gxBSHash :: !DATA
                          } deriving (Show, Eq)

data DHKeyMessage = DHK {gyMpi :: !Integer } deriving (Show, Eq)

data RevealSignatureMessage = RSM { revealedKey :: !DATA
                                  , rsmSig :: !SignatureMessage
                                  } deriving (Eq, Show)

data SignatureMessage = SM { encryptedSignature :: !DATA
                           , macdSignature :: !MAC
                           } deriving (Eq, Show)

data DataMessage = DM { senderKeyID :: !Integer
                      , recipientKeyID :: !Integer
                      , nextDHy :: !Integer
                      , ctrHi :: !CTR
                      , messageEnc :: !DATA
                      , messageMAC :: !DATA
                      }

                   deriving (Show, Eq)

data E2EAkeMessage = DHCommitMessage {unDHCommitMessage :: !DHCommitMessage}
                   | DHKeyMessage{unDHKeyMessage :: !DHKeyMessage}
                   | RevealSignatureMessage{ unRevealSignatureMessage::
                                                   !RevealSignatureMessage}
                   | SignatureMessage{unSignatureMessage :: !SignatureMessage}
                   deriving (Eq, Show)


data E2EParameters = E2EParameters { paramDHPrime :: !Integer
                                   , paramDHGenerator :: !Integer
                                   , paramDHKeySizeBits :: !Integer
                                   , paramEncrypt :: BS.ByteString -- IV
                                                  -> BS.ByteString -- key
                                                  -> BS.ByteString -- payload
                                                  -> BS.ByteString -- ciphertext
                                   , paramEncryptionBlockSize :: !Int
                                   , paramEncryptionKeySize :: !Int
                                   , paramHash :: BS.ByteString -> BS.ByteString
                                   , paramMac  :: BS.ByteString -- macKey
                                               -> BS.ByteString -- Payload
                                               -> BS.ByteString
                                   , paramCheckMac :: BS.ByteString -- macKey
                                                   -> BS.ByteString -- payload
                                                   -> BS.ByteString -- MAC
                                                   -> Bool
                                   }

data E2EGlobals = E2EG { parameters :: !E2EParameters
                       , pubKey :: !PubKey
                       }

data PubKey = PubKey { pubKeyType :: !BS.ByteString
                     , pubKeyData :: !BS.ByteString
                     } deriving (Eq, Ord, Show, Typeable)


data SignatureData = SD { sdPubKey   :: !PubKey
                        , sdKeyID    :: !Integer
                        , sdSig      :: !BS.ByteString
                        } deriving (Eq, Show)

data AuthKeys = KeysRSM -- RevealSignatureMessage
              | KeysSM  -- SignatureMessage


data E2EMessage = E2EAkeMessage {unE2EAkeMessage ::  !E2EAkeMessage}
                | E2EDataMessage {unE2EDataMessage:: !DataMessage}
                  deriving Show

data EndSessionMessage = EndSessionMessage

data MessagingF a = SendMessage !E2EMessage a
                  | RecvMessage (E2EMessage -> a)
                  | Yield !BS.ByteString a
                  | StateChange !MsgState !MsgState a
                  | Log !String a
                  | Sign !BS.ByteString (BS.ByteString -> a)
                  | Verify !PubKey        -- | Public key
                           !BS.ByteString -- | Signature
                           !BS.ByteString -- | Plain Text
                           (VerifyInfo -> a)
                  deriving Functor

type Messaging = Free MessagingF

instance Show a => Show (MessagingF a) where
    show (SendMessage msg f) = "SendMessage{" ++ show msg ++ "}> " ++ show f
    show (RecvMessage _) = "RecvMsg(...)"
    show (Yield y f) = "Yield{" ++ show y ++ "}> " ++ show f
    show (StateChange oldSt newST f)
        = "StateChange{" ++ show oldSt ++ " -> " ++ show newST ++ "}> " ++ show f
    show (Log l f) = "Log{" ++ show l ++ "}> " ++ show f
    show (Sign bs _) = "Sign{" ++ show bs ++ "}(...) "
    show (Verify pkid plain sig _f) = concat $
                                     [ "Verify{key: ", show pkid
                                     , "plaintext: ", show plain
                                     , "signature: ", show sig
                                     , "}> (..)"
                                     ]



type RunState g = Either E2EError (E2EState, g)

data E2ECallbacks = E2EC { onStateChange :: Xmpp.Jid
                                         -> MsgState -- old state
                                         -> MsgState -- new state
                                         -> IO ()
                         , onSmpChallenge :: Xmpp.Jid
                                          -> BS.ByteString
                                          -> VerifyInfo
                                          -> Maybe Text
                                          -> IO ()
                         , onSmpAuthChange :: Xmpp.Jid -> Bool -> IO ()
                         , cSign :: BS.ByteString -> IO BS.ByteString
                         , cVerify :: Xmpp.Jid
                                   -> PubKey
                                   -> BS.ByteString
                                   -> BS.ByteString
                                   -> IO (Maybe VerifyInfo)
                         }

data E2EContext =
    E2EContext { peers :: TMVar (Map.Map Xmpp.Jid
                                 (E2ESession CRandom.SystemRNG))
               , sessRef :: TVar (Maybe Xmpp.Session)
               , globals :: E2EGlobals
               , callbacks :: E2ECallbacks
               }

data Run g = Wait (E2EMessage -> Messaging (RunState g))
           | Done (RunState g)

mapRun :: (E2EState -> E2EState) -> Run g -> Run g
mapRun f (Wait g) = Wait (fmap (fmap (first f)) . g)
mapRun _ (Done (Left e)) = Done $ Left e
mapRun f (Done (Right (r, g))) = Done $ Right (f r, g)


data E2ESession g =
    E2ESession { sE2eGlobals :: E2EGlobals
               , sE2eState :: TMVar (Run g)
               , sSign :: BS.ByteString -> IO BS.ByteString
               , sVerify :: PubKey
                            -> BS.ByteString
                            -> BS.ByteString
                            -> IO (Maybe VerifyInfo)
               , sOnStateChange :: MsgState -> MsgState -> IO ()
               , sOnSmpChallenge :: BS.ByteString
                                 -> VerifyInfo
                                 -> Maybe Text
                                 -> IO ()
               , sOnSmpAuthChange :: Bool -> IO ()
               , sPeer :: Xmpp.Jid
               }

data AKEError = AKESendError Xmpp.IQSendError
              | AKEIQError Xmpp.IQError
              | AKEError E2EError
