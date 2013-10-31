{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
module Pontarius.E2E.Serialize
where

import           Control.Applicative ((<$>), (<*>))
import           Control.Exception (SomeException)
import           Control.Monad
import           Control.Monad.Error
import qualified Crypto.PubKey.DSA as DSA
import           Data.Aeson
import           Data.Aeson.Types (Parser)
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Builder as BSB
import           Data.Conduit (($=),($$), ConduitM, await, yield)
import qualified Data.Conduit.List as CL
import           Data.Foldable (foldMap)
import           Data.List
import           Data.Monoid(mappend)
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import           Data.Word
import           Data.XML.Pickle
import           Data.XML.Types
import           Network.Xmpp.Marshal (xpStanza)
import           Network.Xmpp.Stream (elements)
import           Network.Xmpp.Types (Stanza)
import           Network.Xmpp.Utilities (renderElement)
import           Pontarius.E2E.Types
import           Text.XML.Stream.Parse


-- | Will be [] for x <= 0
unrollInteger :: Integer -> [Word8]
unrollInteger x = reverse $ unfoldr go x
  where
    go x' | x' <= 0    = Nothing
          | otherwise = Just (fromIntegral x', x' `shiftR` 8)

rollInteger :: [Word8] -> Integer
rollInteger = foldl' (\y x -> ((y `shiftL` 8) + fromIntegral x)) 0

encodeInteger :: Integer -> BS.ByteString
encodeInteger = BS.pack . unrollInteger

decodeInteger :: BS.ByteString -> Integer
decodeInteger = rollInteger . BS.unpack


intToB64BS :: Integer -> BS.ByteString
intToB64BS = B64.encode . encodeInteger

intToB64 :: Integer -> Text
intToB64 = Text.decodeUtf8 . intToB64BS

b64ToInt :: Text -> Parser Integer
b64ToInt b64 = do
    Right bs <- return . B64.decode . Text.encodeUtf8 $ b64
    return . decodeInteger $ bs

toMPIBuilder i = let bs = unrollInteger i in BSB.word32BE
                                               (fromIntegral $ length bs)
                                             `mappend` (BSB.word8 `foldMap` bs)

-- | Encode data message for MAC
encodeMessageBytes :: DataMessage -> BS.ByteString
encodeMessageBytes msg = BS.concat . BSL.toChunks . BSB.toLazyByteString $
                           foldMap toMPIBuilder [ senderKeyID msg
                                                , recipientKeyID msg
                                                , nextDHy msg
                                                ]
                           `mappend` BSB.word32BE (fromIntegral . BS.length
                                                     $ ctrHi msg)
                           `mappend` BSB.byteString (ctrHi msg)
                           `mappend` BSB.word32BE (fromIntegral . BS.length
                                                     $ messageEnc msg)
                           `mappend` BSB.byteString (messageEnc msg)
--------------------------------------
-- JSON ------------------------------
--------------------------------------

pubKeyFromJson :: Value -> Parser DSA.PublicKey
pubKeyFromJson = withObject "DSA Public Key" dsaPBFJ
  where
    dsaPBFJ  o = DSA.PublicKey <$> paramsFJ o
                               <*> (b64ToInt =<< o .: "y")
    paramsFJ o = DSA.Params <$> (b64ToInt =<< o .: "p")
                            <*> (b64ToInt =<< o .: "g")
                            <*> (b64ToInt =<< o .: "q")

pubKeyToJson :: DSA.PublicKey -> Value
pubKeyToJson (DSA.PublicKey (DSA.Params p g q) y)  = object [ "p" .=  intToB64 p
                                                            , "g" .=  intToB64 g
                                                            , "q" .=  intToB64 q
                                                            , "y" .=  intToB64 y
                                                            ]

signatureFromJson :: Value -> Parser DSA.Signature
signatureFromJson = withObject "DSA SIgnature" dsaSFJ
  where
    dsaSFJ o = DSA.Signature <$> (b64ToInt =<< o .: "r")
                             <*> (b64ToInt =<< o .: "s")

signatureToJson :: DSA.Signature -> Value
signatureToJson (DSA.Signature r s) = object [ "r" .= intToB64 r
                                             , "s" .= intToB64 s
                                             ]

instance FromJSON SignatureData where
    parseJSON (Object v) = do
        tp <- v .: "type"
        guard (tp == ("DSA" :: String ))
        pub <- pubKeyFromJson =<< v .: "pubkey"
        kid <- v .: "keyID"
        sig <- signatureFromJson =<< v .: "signature"
        return $ SD pub kid sig
    parseJSON _ = mzero

instance ToJSON SignatureData where
    toJSON SD{..} = object [ "type" .= ("DSA" :: String)
                           , "pubkey" .= pubKeyToJson sdPub
                           , "keyID" .= sdKeyID
                           , "signature" .= signatureToJson sdSig
                           ]

-- See Issue 142 in AESON: https://github.com/bos/aeson/issues/142
jsonDecode d = case eitherDecode' (BSL.fromChunks [d]) of
    Right x -> return x
    Left e -> throwError $ ProtocolError (DeserializationError $ BS8.unpack d) e

---------------------------
-- XML --------------------
---------------------------

e2eNs :: Text
e2eNs = "yabasta-ake-1:0"

e2eName :: Text -> Name
e2eName n = Name n (Just e2eNs) Nothing

liftLeft :: (t -> a) -> Either t b -> Either a b
liftLeft f  (Left e) = Left (f e)
liftLeft _f (Right r) = Right r

b64Elem :: Text -> PU [Node] BS.ByteString
b64Elem name = xpElemNodes (e2eName name)
                (xpContent $
                 xpPartial (liftLeft Text.pack . B64.decode . Text.encodeUtf8)
                           (Text.decodeUtf8 . B64.encode))

b64IElem :: Integral i => Text -> PU [Node] i
b64IElem name = xpWrap (fromIntegral . decodeInteger)
                       (encodeInteger . fromIntegral) $
                           b64Elem name


dhCommitMessageXml :: PU [Node] DHCommitMessage
dhCommitMessageXml = xpWrap  (uncurry DHC) (\(DHC e h) -> (e, h)) $
    xpElemNodes (e2eName "dh-commit-message") $
                      xp2Tuple (b64Elem "ae")
                               (b64Elem "hash")

dhKeyMessageXml :: PU [Node] DHKeyMessage
dhKeyMessageXml = xpWrap DHK gyMpi
                  . xpElemNodes (e2eName "dh-key-message") $
                      b64IElem "bp"

revealSignatureMessageXml :: PU [Node] RevealSignatureMessage
revealSignatureMessageXml = xpWrap (\(rk, es, ms) -> (RSM rk (SM es ms)))
                                   (\(RSM rk (SM es ms)) -> (rk, es, ms)) .
                            xpElemNodes (e2eName "reveal-signature-message") $
                                xp3Tuple (b64Elem "key")
                                         (b64Elem "encsig")
                                         (b64Elem "encsigmac")

signatureMessageXml :: PU [Node] SignatureMessage
signatureMessageXml = xpWrap (uncurry SM) (\(SM es ms) -> (es, ms)) .
                       xpElemNodes (e2eName "signature-message") $
                           xp2Tuple (b64Elem "encsig")
                                    (b64Elem "encsigmac")


akeMessageSelector :: Num a => E2EAkeMessage -> a
akeMessageSelector DHCommitMessage{}        = 0
akeMessageSelector DHKeyMessage{}           = 1
akeMessageSelector RevealSignatureMessage{} = 2
akeMessageSelector SignatureMessage{}       = 3

akeMessageXml :: PU [Element] E2EAkeMessage
akeMessageXml = xpUnliftElems $
                xpChoice akeMessageSelector
                      [ xpWrap DHCommitMessage unDHCommitMessage
                               dhCommitMessageXml
                      , xpWrap DHKeyMessage unDHKeyMessage
                               dhKeyMessageXml
                      , xpWrap RevealSignatureMessage
                               unRevealSignatureMessage
                               revealSignatureMessageXml
                      , xpWrap SignatureMessage
                               unSignatureMessage
                               signatureMessageXml
                      ]


endSessionMessageXml :: PU [Element] ()
endSessionMessageXml = xpUnliftElems $ xpElemBlank (e2eName "end-session")

dataMessageXml :: PU [Element] DataMessage
dataMessageXml = xpUnliftElems .
                 xpWrap (\(skid, rkid, ndh, ctr, menc, mmac) ->
                          DM skid rkid ndh ctr menc mmac)
                        (\(DM skid rkid ndh ctr menc mmac) ->
                          (skid, rkid, ndh, ctr, menc, mmac)) $
                 xpElemNodes (e2eName "content") $
                    xp6Tuple (b64IElem"sender-key-id"    )
                             (b64IElem "recipient-key-id")
                             (b64IElem "next-key"        )
                             (b64Elem "counter"          )
                             (b64Elem "data"             )
                             (b64Elem "mac"              )

e2eMessageSelector :: Num a => E2EMessage -> a
e2eMessageSelector E2EAkeMessage{} = 0
e2eMessageSelector E2EDataMessage{} = 1
e2eMessageSelector E2EEndSessionMessage{} = 2

e2eMessageXml = xpChoice e2eMessageSelector
                [ xpWrap E2EAkeMessage unE2EAkeMessage akeMessageXml
                , xpWrap E2EDataMessage unE2EDataMessage dataMessageXml
                , xpConst E2EEndSessionMessage endSessionMessageXml
                ]

e2eRequestXml :: PU [Element] ()
e2eRequestXml = xpUnliftElems .
                xpConst () $ xpElemBlank (e2eName "session-request")

e2eResponseXml :: PU Element Bool
e2eResponseXml = xpRoot . xpUnliftElems .
                 xpElemNodes (e2eName "session-response") $
                 xpChoice responseSelector
                 [ xpConst True  $ xpElemBlank (e2eName "proceed")
                 , xpConst False $ xpElemBlank (e2eName "declined")
                 ]
  where
    responseSelector True = 0
    responseSelector False = 0

filterOutJunk :: Monad m => ConduitM Event Event m ()
filterOutJunk = go
  where
    go = do
        next <- await
        case next of
            Nothing -> return () -- This will only happen if the stream is closed.
            Just n -> do
                case n of
                    EventBeginElement{}   -> yield n
                    EventEndElement{}     -> yield n
                    EventContent{}        -> yield n
                    EventCDATA{}          -> yield n
                    EventBeginDocument{}  -> return ()
                    EventEndDocument{}    -> return ()
                    EventBeginDoctype{}   -> return ()
                    EventEndDoctype{}     -> return ()
                    EventInstruction{}    -> return ()
                    EventComment{}        -> return ()
                go


xpStanza' :: PU Element Stanza
xpStanza' = xpRoot . xpUnliftElems $ xpStanza

renderStanza :: Stanza -> BS.ByteString
renderStanza = renderElement . pickle xpStanza'

readStanzas :: BS.ByteString -> Either String [Stanza]
readStanzas bs = es >>= mapM (\el -> case unpickle xpStanza' el of
                                   Left e -> Left $ ppUnpickleError e
                                   Right r -> Right r
                             )
  where
    es = case CL.sourceList [bs] $= parseBytes def $= filterOutJunk $= elements
              $$ CL.consume of
        Left e -> Left $ show (e :: SomeException)
        Right r -> Right r
