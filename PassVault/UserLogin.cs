using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace PassVault
{
    public static class UserLogin
    {
        public static string username;
        public static void Register(string i_username, string masterPassword)
        {
            username = i_username;

            if (Validate(username, masterPassword))
            {
                // User creation and all his new data
                DataStore.SaveData(username);
                byte[] salt = GenerateSalt();
                DataStore.SaveData(Globals.Salt, salt);

                byte[] secretKey = SecretKey.GenerateSecretKey(username);
                DataStore.SaveData(Globals.SecretKey, secretKey);

                RSA rsa = new RSA();
                byte[] publicKey = rsa.getPublicKey().ToByteArray();
                DataStore.SaveData(Globals.RSAPublicKey, publicKey);
                byte[] privateKey = rsa.getPrivateKey().ToByteArray();
                DataStore.SaveData(Globals.RSAPrivateKey, privateKey);

                byte[] vaultKey = VaultKey.GenerateVaultKey();
                byte[] encryptedVaultKey = rsa.Encrypt(vaultKey);
                DataStore.SaveData(Globals.VaultKey, encryptedVaultKey);

                byte[] encryptedVerifier = AES.StartAES(Encoding.ASCII.GetBytes(Globals.EncryptionVerifier)
                    ,AES.AES_Type.Encrypt, username);
                DataStore.SaveData(Globals.EncryptionVerifier, encryptedVerifier);

                byte[] masterUnlockKey = DeriveMasterUnlockKey(Encoding.ASCII.GetBytes(masterPassword), username);
                DataStore.SaveData(Globals.MasterUnlockKey, masterUnlockKey);
            }
        }

        public static void Login(string username, string masterPassword)
        {
            byte[] decryptedVaultKey = DataStore.GetData(Globals.VaultKey);
            byte[] privateKey = DataStore.GetData(Globals.RSAPrivateKey);

            byte[] encryptedVerifier = DataStore.GetData(Globals.EncryptionVerifier);
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

        private static bool Validate(string username, string masterPassword)
        {
            MainWindow mw = (MainWindow)Application.Current.MainWindow;
            if (DataStore.IsExists(username))
            {
                mw.RegisterOutputTB.Text = "Error: Username already taken.";
                return false;
            }
            else if (masterPassword.Length == 0)
            {
                mw.RegisterOutputTB.Text = "Error: Empty Username.";
                return false;
            }
            else if (masterPassword.Length == 0)
            {
                mw.RegisterOutputTB.Text = "Error: Empty Password.";
                return false;
            }
            //BloomFilter bloomFilter = new BloomFilter((float)0.001);
            //if(bloomFilter.Find(masterPassword))
            //{
            //    mw.RegisterOutputTB.Text = "Error: Password is too weak. Try again!";
            //    return false;
            //}

            mw.RegisterOutputTB.Text = "User created successfully!";
            return true;
        }

        private static byte[] DeriveMasterUnlockKey(byte[] masterPassword, string username)
        {
            byte[] salt = DataStore.GetData(Globals.Salt);
            byte[] hashedPassword = PBKDF2.PerformPBKDF(masterPassword, salt);

            byte[] secretKey = DataStore.GetData(Globals.SecretKey);
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
