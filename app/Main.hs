{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
module Main where


import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.OAEP
import Crypto.Hash
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Random          ( MonadRandom, getRandomBytes )
import Crypto.Error


import System.Environment     ( getArgs )
import System.Directory       ( doesFileExist, copyFile )

import Control.Monad.IO.Class ( liftIO )

import Data.Functor           ((<&>))
import Data.ByteString        ( ByteString )
import qualified Data.ByteString as BS
import Data.ByteString.Char8  ( pack, unpack)

-- import Options.Applicative -- later


main :: IO ()
main = do
  args <- getArgs
  case args of
    [] -> error "no command specified!"
    (command : xs) -> do

      case command of
        "exchange" -> commandExchange xs
        "encrypt"  -> commandEncrypt xs
        "decrypt"  -> commandDecrypt xs
        "new"      -> commandNew
        "-h"       -> helpCommand
        "--help"   -> helpCommand
        "help"     -> helpCommand
        _          -> error $ "unknown command " <> command


helpCommand :: IO () -- TODO
helpCommand = putStrLn 
  "PComm - simple private messages over third party systems\n\n\
  \Usage: PComm [command] [args..]\n\n\
  \Available commands:\n\
  \\t new      \t\t\t Generate new random RSA key pair and AES256 key\n\
  \\t exchange \t\t\t Key exchange procedure... mostly manual...\n\
  \\t encrypt  \t\t\t Encrypt a message to a file, treats all arguments as words of a message\n\
  \\t decrypt  \t\t\t Decrypt a message from a file, takes one argument: file path to the message\n\
  \\t help     \t\t\t Shows this message\n"


commandExchange :: [String] -> IO ()
commandExchange args = do
  -- check for existance of local key pair
  pubExists <- doesFileExist "./local/pub"
  prvExists <- doesFileExist "./local/prv"
  aesExists <- doesFileExist "./local/aes"
  
  case (pubExists && prvExists && aesExists, args) of
    (True, "server" : _) -> do
      putStrLn "Public key is in './local/pub' send it over to the other person\n"
      putStrLn "Put the encryptedAES file in './foreign/encryptedAES' then press [ENTER]"
      _ <- getLine
      
      prv  <- readFile "./local/prv" <&> read :: IO PrivateKey
      BS.readFile "./foreign/encryptedAES" <&> decryptRSA prv >>= \case
        Left err  -> error $ "Could not decrypt aes key " <> show err
        Right aes -> do
          putStrLn "Writing decrypted aes ley to './shared/aes'"
          BS.writeFile "./shared/aes" aes

      putStrLn "Key exchange on your side is finished!"
      
    
    (True, _) -> do
      copyFile "./local/aes" "./shared/aes"
      putStrLn "Put the other's public key in './foreign/pub' then press [ENTER]"
      _ <- getLine

      pub <- readFile "./foreign/pub" <&> read :: IO PublicKey
      
      BS.readFile "./shared/aes" >>= encryptRSA pub >>= \case
        Left err    -> error $ "Could not encrypt aes key " <> show err
        Right eaes  -> do
          BS.writeFile "./encryptedAES" eaes
          putStrLn "Writing encrypted aes key to './encryptedAES' send it over to the other person\n"

      putStrLn "When sent key exchange on your side is finished!"
    

    (False, _) -> putStrLn "Keys are incomplete, run the `new` command to generate them\n(also mind that running it will override old keys)\n"


commandEncrypt :: [String] -> IO ()
commandEncrypt [] = putStrLn "need a message to encrypt"
commandEncrypt message = do
  aes <- readFile "./shared/aes" <&> read :: IO AES256Key
  
  case encryptAES256 aes (pack $ unwords message) of
    Left err  -> error $ "Could not encrypt message " <> show err
    Right enc -> do
      putStrLn "Encrypted message is in './encryptedMessage'"
      BS.writeFile "./encryptedMessage" enc


commandDecrypt :: [String] -> IO ()
commandDecrypt [] = putStrLn "Need a message to decrypt [file path]"
commandDecrypt (filepath : _) = do
  aes <- readFile "./shared/aes" <&> read :: IO AES256Key
  enc <- BS.readFile filepath
  
  case decryptAES256 aes enc of
    Left err      -> error $ "Could not decrypt message " <> show err
    Right message -> putStrLn (unpack message)


commandNew :: IO ()
commandNew = do
  (pub, prv) <- generateKeyPair
  aeskey     <- generateAESKey
  
  putStrLn "Writing keys into './local/[pub, prv, aes]'"
  writeFile "./local/pub" (show pub)
  writeFile "./local/prv" (show prv)
  writeFile "./local/aes" (show aeskey)


--    # Cryptography
encryptRSA :: MonadRandom m => PublicKey -> ByteString -> m (Either Error ByteString)
encryptRSA = encrypt (defaultOAEPParams SHA256)

-- since the use is manual we dont need a blinder
decryptRSA :: PrivateKey -> ByteString -> Either Error ByteString
decryptRSA = decrypt Nothing (defaultOAEPParams SHA256) 

-- random RSA key pair
generateKeyPair :: IO (PublicKey, PrivateKey)
generateKeyPair = generate 512 65537


-- generate random AES256 key
generateAESSecret :: MonadRandom m => m AES256Secret
generateAESSecret = getRandomBytes 32

generateIV :: MonadRandom m => m AES256IV
generateIV = do
  bytes <- getRandomBytes (blockSize (undefined :: AES256))
  case makeIV bytes :: Maybe (IV AES256) of
    Nothing -> error "could not generate IV"
    Just _ -> return bytes


generateAESKey :: IO AES256Key
generateAESKey = do
  a <- generateAESSecret
  b <- generateIV
  return (a, b)

-- initialize a block cipher
initCipher :: AES256Secret -> Either CryptoError AES256
initCipher k = case cipherInit k of
  CryptoFailed e -> Left e
  CryptoPassed a -> Right a


encryptAES256 :: AES256Key -> ByteString -> Either CryptoError ByteString
encryptAES256 (secretKey, initIV) msg =
  case initCipher secretKey of
    Left e -> Left e
    Right c -> case makeIV initIV of
      Nothing -> Left CryptoError_IvSizeInvalid
      Just iv -> Right $ ctrCombine c iv msg

decryptAES256 :: AES256Key -> ByteString -> Either CryptoError ByteString
decryptAES256 = encryptAES256

type AES256Secret = ByteString
type AES256IV     = ByteString
type AES256Key    = (ByteString, ByteString)

