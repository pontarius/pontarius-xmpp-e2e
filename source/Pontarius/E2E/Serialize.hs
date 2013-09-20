{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
module Pontarius.E2E.Serialize
where

import Control.Applicative ((<$>), (<*>))
import           Control.Monad
import qualified Crypto.PubKey.DSA as DSA
import           Data.Aeson
import           Data.Aeson.Types (Parser)
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import           Data.List
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import           Data.Word
import           Data.XML.Pickle
import           Data.XML.Types
import           Pontarius.E2E.Types


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
    return . decodeInteger.unpack $ bs

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


messageSelector :: Num a => E2EAkeMessage -> a
messageSelector DHCommitMessage{}        = 0
messageSelector DHKeyMessage{}           = 1
messageSelector RevealSignatureMessage{} = 2
messageSelector SignatureMessage{}       = 3

akeMessageXml :: PU [Node] E2EAkeMessage
akeMessageXml = xpAlt messageSelector [ xpWrap DHCommitMessage unDHCommitMessage
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

dataMessageXml :: PU [Node] DataMessage
dataMessageXml = xpWrap (\(skid, rkid, ndh, ctr, menc, mmac) ->
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
