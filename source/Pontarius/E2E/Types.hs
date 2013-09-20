{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveFunctor #-}
module Pontarius.E2E.Types
where

import qualified Control.Monad.CryptoRandom as CR
import           Control.Monad.Error
import qualified Crypto.PubKey.DSA as DSA
import qualified Data.ByteString as BS
import           Data.Typeable (Typeable)


type CTR = BS.ByteString
type MAC = BS.ByteString
type DATA = BS.ByteString

data DHKeyPair = DHKeyPair { pub  :: !Integer
                           , priv :: !Integer
                           } deriving Show

data MsgState = MsgStatePlaintext
              | MsgStateEncrypted
              | MsgStateFinished
              deriving (Eq, Show)

data SmpMessaging a = SendSmpMessage SmpMessage (SmpMessaging a)
                    | RecvSmpMessage Int (SmpMessage -> SmpMessaging a)
                    | SmpReturn a
                 deriving Functor

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

data E2EError = WrongState
              | RandomGenError CR.GenError
              | InstanceTagRange
              | NoPeerDHKey -- theirCurrentKey is Nothing
              | ProtocolError ProtocolError -- One of the checks failed
                deriving (Show, Eq, Typeable)

instance Error E2EError where
    noMsg = WrongState

data AuthState = AuthStateNone
               | AuthStateAwaitingDHKey BS.ByteString
               | AuthStateAwaitingRevealsig DHCommitMessage
               | AuthStateAwaitingSig
                 deriving Show

data SmpMessage = SmpMessage1 {g2a, c2, d2, g3a, c3, d3 :: !Integer }
                | SmpMessage2 {g2b, c2', d2', g3b, c3'
                              , d3' , pb, qb, cp, d5, d6 :: !Integer}
                | SmpMessage3 {pa, qa, cp', d5, d6, ra, cr, d7 :: !Integer}
                | SmpMessage4 {rb, cr, d7' :: !Integer}
                | SmpMessage1Q { question :: BS.ByteString
                               , g2a, c2, d2, g3a, c3, d3 :: !Integer }

                  deriving (Show, Eq)

data E2EState = E2EState { authState        :: !AuthState
                         , msgState         :: !MsgState
                         , ourKeyID         :: !Integer -- KeyID of ourCurrentKey
                         , theirPublicKey   :: !(Maybe DSA.PublicKey) -- DSA
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
                         , ssid             :: Maybe BS.ByteString
                           -- SMP ------------------------------
                         , verified         :: Bool
                         , smpState         :: Maybe (SmpMessaging (Either E2EError Bool))
                         }

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

data MessageKeys = MK { sendAES
                      , sendMAC
                      , recvAES
                      , recvMAC :: !BS.ByteString
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

data DataMessage = DM { senderKeyID :: Integer
                      , recipientKeyID :: Integer
                      , nextDHy :: Integer
                      , ctrHi :: CTR
                      , messageEnc :: DATA
                      , messageMAC :: DATA
                      }

                   deriving (Show, Eq)

data E2EAkeMessage = DHCommitMessage {unDHCommitMessage :: !DHCommitMessage}
                   | DHKeyMessage{unDHKeyMessage :: !DHKeyMessage}
                   | RevealSignatureMessage{ unRevealSignatureMessage::
                                                   !RevealSignatureMessage}
                   | SignatureMessage{unSignatureMessage :: !SignatureMessage}
                   deriving (Eq, Show)


data E2EParameters = E2EParameters { dhPrime :: Integer
                                   , dhGenerator :: Integer
                                   , dhKeySizeBits :: Integer
                                   , encryptionCtr :: BS.ByteString -- ^ IV
                                                   -> BS.ByteString -- ^ key
                                                   -> BS.ByteString -- ^ payload
                                                   -> BS.ByteString
                                                      -- ^ ciphertext
                                   , encryptionBlockSize :: Int
                                   , paramHash :: BS.ByteString -> BS.ByteString
                                   , paramMac  :: BS.ByteString -- ^ macKey
                                               -> BS.ByteString -- ^ Payload
                                               -> BS.ByteString
--                                   , sign :: ???
                                   }

type DSAKeyPair = (DSA.PublicKey, DSA.PrivateKey)

data E2EGlobals = E2EG { parameters :: E2EParameters
                       , dsaKeyPair :: DSAKeyPair
                       }

data SignatureData = SD { sdPub   :: DSA.PublicKey
                        , sdKeyID :: Integer
                        , sdSig   :: DSA.Signature
                        } deriving (Eq, Show)

data AuthKeys = KeysRSM -- RevealSignatureMessage
              | KeysSM  -- SignatureMessage
