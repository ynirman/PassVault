using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;


namespace PassVault
{
    public static class UserLogin
    {
        public static void Login()
        {
            string username = "Erlich";

            // User\password check
            if (true)
            {
                //byte[] masterUnlockKey = DeriveMasterUnlockKey();
                if (true)
                {
                    // First Login
                    byte[] salt = GenerateSalt();
                    byte[] secretKey = SecretKey.GenerateSecretKey(username);
                    byte[] vaultKey = VaultKey.GenerateVaultKey();

                    DataStore.SaveData("salt" ,Encoding.ASCII.GetBytes("ABCXZDSA"));
                    byte[] newsalt = DataStore.GetData("salt");
                    // Store salt, secretKey and vaultKey
                    

                    // Store RSA Pair
                }
                else
                {
                    // Not First Login

                }
            }
            else
            {
                // User login failed
            }
        }

        private static byte[] GenerateSalt()
        {
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            byte[] salt = new byte[16];
            rngCsp.GetBytes(salt);

            return salt;
        }

        //private static byte[] DeriveMasterUnlockKey()
        //{
        //    // Get pass and salt from KeyStore?
        //    string mypass = " a a ";
        //    string mysalt = "1234567887654321123456788765432312321";
        //    byte[] masterPassword = Encoding.ASCII.GetBytes(mypass);
        //    byte[] salt = Encoding.ASCII.GetBytes(mysalt); ;

        //    byte[] hashedPassword = PBKDF2.PerformPBKDF(masterPassword, salt);
        //    // get SecretKey from store
        //    if(true)
        //    {

        //    }


        //}
    }
}
