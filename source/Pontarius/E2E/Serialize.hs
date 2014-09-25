{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
module Pontarius.E2E.Serialize where

import           Control.Applicative
import           Control.Exception (SomeException)
import           Control.Monad.Catch (throwM)
import           Control.Monad.Except
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BS8
import           Data.Conduit (($=),($$), ConduitM, await, yield, transPipe)
import qualified Data.Conduit.List as CL
import           Data.List
import           Data.Serialize
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import           Data.Word
import           Data.XML.Pickle
import           Data.XML.Types
import           Network.Xmpp (XmppFailure)
import           Network.Xmpp.Internal (xpStanza, elements, renderElement, Stanza)
import           Pontarius.E2E.Types
import           Text.XML.Stream.Parse


-- Binary encodings
------------------------------

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

putMPI :: Integer -> PutM ()
putMPI = putData . encodeInteger

getMPI :: Get Integer
getMPI = decodeInteger <$> getData

-- | Encode data message for MAC
encodeMessageBytes :: DataMessage -> BS.ByteString
encodeMessageBytes msg = runPut $ do
    putMPI $ senderKeyID msg
    putMPI $ recipientKeyID msg
    putMPI $ nextDHy msg
    putData $ ctrHi msg
    putData $ messageEnc msg

putData :: BS8.ByteString -> PutM ()
putData bs = do
    putWord32be . fromIntegral $ BS.length bs
    putByteString bs

getData :: Get BS8.ByteString
getData = do
    ln <- getWord32be
    getByteString (fromIntegral ln)

putPubkey :: PubKey -> PutM ()
putPubkey (PubKey tp' dt) = do
    putData tp'
    putData dt

encodePubkey :: PubKey -> BS.ByteString
encodePubkey = runPut . putPubkey

getPubKey :: Get PubKey
getPubKey = PubKey <$> getData <*> getData

instance Serialize SignatureData where
    put sd = do
        putPubkey (sdPubKey sd)
        putMPI $ sdKeyID sd
        putData $ sdSig sd
    get = SD <$> getPubKey <*> getMPI <*> getData

---------------------------
-- XML --------------------
---------------------------

e2eNs :: Text
e2eNs = "yabasta-ake-1:0"

e2eName :: Text -> Name
e2eName n = Name n (Just e2eNs) Nothing

smpNs :: Text
smpNs = "yabasta-smp-1:0"

smpName :: Text -> Name
smpName n = Name n (Just smpNs) Nothing

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

smpMessageSelector :: Num a => SmpMessage -> a
smpMessageSelector SmpMessage1{} = 0
smpMessageSelector SmpMessage2{} = 1
smpMessageSelector SmpMessage3{} = 2
smpMessageSelector SmpMessage4{} = 3

xpSmpMessage1 :: PU [Node] SmpMessage
xpSmpMessage1 = xpWrap (\(q, (i1, i2, i3, i4, i5, i6))
                              -> SmpMessage1 q i1 i2 i3 i4 i5 i6)
                           (\(SmpMessage1 q i1 i2 i3 i4 i5 i6) ->
                             (q, (i1, i2, i3, i4, i5, i6))) $
    xpElem (smpName "message1") (xpAttribute' "question" xpId) $
    xp6Tuple (b64IElem "g2a") (b64IElem "c2") (b64IElem "d3") (b64IElem "g3a")
             (b64IElem "c3")  (b64IElem "d3")

xpSmpMessage2 :: PU [Node] SmpMessage
xpSmpMessage2 = xpWrap (\((i1, i2, i3, i4, i5, i6), (i7, i8, i9, i10, i11))
                              -> SmpMessage2 i1 i2 i3 i4 i5 i6 i7 i8 i9 i10 i11)
                       (\(SmpMessage2 i1 i2 i3 i4 i5 i6 i7 i8 i9 i10 i11)
                          -> ((i1, i2, i3, i4, i5, i6), (i7, i8, i9, i10, i11))) $
    xpElemNodes (smpName "message2")  $
    xp2Tuple ( xp6Tuple (b64IElem "g2b") (b64IElem "c2p") (b64IElem "d2p")
                       (b64IElem "g3b") (b64IElem "c3p")  (b64IElem "d3p"))
            ( xp5Tuple (b64IElem "pb") (b64IElem "qb") (b64IElem "cp")
                       (b64IElem "d5") (b64IElem "d6"))

xpSmpMessage3 :: PU [Node] SmpMessage
xpSmpMessage3 = xpWrap (\((i1, i2, i3, i4, i5, i6), (i7, i8))
                              -> SmpMessage3 i1 i2 i3 i4 i5 i6 i7 i8 )
                       (\(SmpMessage3 i1 i2 i3 i4 i5 i6 i7 i8 )
                          -> ((i1, i2, i3, i4, i5, i6), (i7, i8))) $
    xpElemNodes (smpName "message3")  $
    xp2Tuple ( xp6Tuple (b64IElem "pa") (b64IElem "qa") (b64IElem "cpp")
                       (b64IElem "d5") (b64IElem "d6")  (b64IElem "ra"))
            ( xp2Tuple (b64IElem "cr") (b64IElem "d7p"))

xpSmpMessage4 :: PU [Node] SmpMessage
xpSmpMessage4 = xpWrap (\(i1, i2, i3) -> SmpMessage4 i1 i2 i3)
                       (\(SmpMessage4 i1 i2 i3) -> (i1, i2, i3)) $
    xpElemNodes (smpName "message4")  $
    xp3Tuple (b64IElem "rb") (b64IElem "cr") (b64IElem "d7")

xpSmpMessage :: PU [Node] SmpMessage
xpSmpMessage = xpChoice smpMessageSelector $
                  [ xpSmpMessage1
                  , xpSmpMessage2
                  , xpSmpMessage3
                  , xpSmpMessage4
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

e2eMessageXml :: PU [Element] E2EMessage
e2eMessageXml = xpChoice e2eMessageSelector
                [ xpWrap E2EAkeMessage unE2EAkeMessage akeMessageXml
                , xpWrap E2EDataMessage unE2EDataMessage dataMessageXml
                ]

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
    es = case CL.sourceList [bs] $= parseBytes def $= filterOutJunk
              $= liftError elements $$ CL.consume of
        Left e -> Left $ show (e :: SomeException)
        Right r -> Right r
    liftError :: ConduitM i o (ExceptT XmppFailure (Either SomeException)) r
              -> ConduitM i o (Either SomeException) r
    liftError = transPipe$ \f -> do
        res <- runExceptT f
        case res of
            Left e -> throwM e
            Right r -> return r
