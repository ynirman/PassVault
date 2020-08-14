using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace PassVault
{
    public static class UserLogin
    {
        public static void Register(string username, string masterPassword)
        {
            if (Validate(username, masterPassword))
            {
                // User creation and all his new data
                DataStore.SaveData(username);
                byte[] salt = GenerateSalt();
                DataStore.SaveData(Globals.Salt, salt, username);
                byte[] secretKey = SecretKey.GenerateSecretKey(username);
                DataStore.SaveData(Globals.SecretKey, secretKey, username);
                byte[] vaultKey = VaultKey.GenerateVaultKey();
                // TODO: Create RSA Pair, Encrypt VaultKey. Encrypt Private Key with MUK
                DataStore.SaveData(Globals.VaultKey, vaultKey, username);
                // TODO Store RSA Pair

                byte[] encryptedVerifier = AES.StartAES(Encoding.ASCII.GetBytes(Globals.EncryptionVerifier)
                    , AES.AES_Type.Encrypt, username);
                DataStore.SaveData(Globals.EncryptionVerifier, encryptedVerifier, username);

                byte[] masterUnlockKey = DeriveMasterUnlockKey(Encoding.ASCII.GetBytes(masterPassword), username);
                DataStore.SaveData(Globals.MasterUnlockKey, masterUnlockKey, username);
            }
        }

        public static void Login(string username, string masterPassword)
        {
            byte[] vaultKey = DataStore.GetData(Globals.VaultKey, username);

            byte[] encryptedVerifier = DataStore.GetData(Globals.EncryptionVerifier, username);
            byte[] decryptedVerifier = AES.StartAES(encryptedVerifier,
                AES.AES_Type.Decrypt, username);

            if(decryptedVerifier == Encoding.ASCII.GetBytes(Globals.EncryptionVerifier))
            {

            }

            // User\password check
            if (true)
            {
                // if First Login
                if (true)
                {
                }

                byte[] MUK = DeriveMasterUnlockKey(Encoding.ASCII.GetBytes(masterPassword), username);
            }
            else
            {
                // Failed Login
            }
        }

        private static bool Validate(string username, string password)
        {
            MainWindow mw = (MainWindow)Application.Current.MainWindow;
            if (DataStore.IsExists(username))
            {
                mw.RegisterOutputTB.Text = "Error: Username already taken.";
                return false;
            }
            else if (username.Length == 0)
            {
                mw.RegisterOutputTB.Text = "Error: Empty Username.";
                return false;
            }
            else if (password.Length == 0)
            {
                mw.RegisterOutputTB.Text = "Error: Empty Password.";
                return false;
            }

            mw.RegisterOutputTB.Text = "User created successfully!";
            return true;
        }

        private static byte[] DeriveMasterUnlockKey(byte[] masterPassword, string username)
        {
            byte[] salt = DataStore.GetData(Globals.Salt, username);
            byte[] hashedPassword = PBKDF2.PerformPBKDF(masterPassword, salt);

            byte[] secretKey = DataStore.GetData(Globals.SecretKey, username);
            byte[] expandedSecretKey = MyHKDF.KeyExpansion(32, secretKey);

            return XOR(hashedPassword, expandedSecretKey);
        }

        private static byte[] GenerateSalt()
        {
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            byte[] salt = new byte[16];
            rngCsp.GetBytes(salt);

            return salt;
        }

        public static byte[] XOR(byte[] a, byte[] b)
        {
            byte[] result = new byte[32];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }

            return result;
        }
    }
}
