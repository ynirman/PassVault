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
        public static void Register(string username, string password)
        {
            if (Validate(username, password))
            {
                DataStore.SaveData(username);
            }
        }

        private static bool Validate(string username, string password)
        {
            MainWindow mw = (MainWindow)Application.Current.MainWindow;
            if(DataStore.IsExists(username))
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

        public static void Login()
        {
            //SecureString(?)
            string username = "Erlich";
            string masterPassword = "hunter2";

            // User\password check
            if (true)
            {
                // if First Login
                if (true)
                {
                    byte[] salt = GenerateSalt();
                    DataStore.SaveData(Globals.Salt, salt);
                    byte[] secretKey = SecretKey.GenerateSecretKey(username);
                    DataStore.SaveData(Globals.SecretKey, secretKey);
                    byte[] vaultKey = VaultKey.GenerateVaultKey();
                    DataStore.SaveData(Globals.VaultKey, vaultKey);
                    // TODO: Create RSA Pair, Encrypt VaultKey. Encrypt Private Key with MUK
                    // Store RSA Pair
                }

                byte[] MUK = DeriveMasterUnlockKey(Encoding.ASCII.GetBytes(masterPassword));
            }
            else
            {
                // Failed Login
            }
        }

        private static byte[] DeriveMasterUnlockKey(byte[] masterPassword)
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
