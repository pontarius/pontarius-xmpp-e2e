{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
module Pontarius.E2E.Serialize
where

import           Control.Applicative((<$>), (<*>), (<|>))
import           Control.Monad
import           Control.Monad (replicateM)
import qualified Crypto.PubKey.DSA as DSA
import           Data.Aeson
import           Data.Aeson.Types (Parser)
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BSL
import           Data.Char (ord)
import           Data.List
import           Data.Monoid (mconcat, mappend)
import           Data.Serialize
import           Data.Text (Text)
import qualified Data.Text.Encoding as Text
import           Data.Word
import           Numeric
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
intToB64BS = B64.encode . BS.pack . unrollInteger

intToB64 :: Integer -> Text
intToB64 = Text.decodeUtf8 . intToB64BS

b64ToInt :: Text -> Parser Integer
b64ToInt b64 = do
    Right bs <- return . B64.decode . Text.encodeUtf8 $ b64
    return . rollInteger . BS.unpack $ bs

pubKeyFromJson = withObject "DSA Public Key" dsaPBFJ
  where
    dsaPBFJ  o = DSA.PublicKey <$> paramsFJ o
                               <*> (b64ToInt =<< o .: "y")
    paramsFJ o = DSA.Params <$> (b64ToInt =<< o .: "p")
                            <*> (b64ToInt =<< o .: "g")
                            <*> (b64ToInt =<< o .: "q")

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
