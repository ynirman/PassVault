using System;
using System.Collections.Generic;
using System.Text;

namespace PassVault
{
    public static class UserLogin
    {
        public static void Login()
        {
            string username = "erlich";

            // User\password check
            if (true)
            {
                if (true)
                {
                    // First Login
                    string secretKey = SecretKey.GenerateSecretKey(username);
                    byte[] vaultKey = VaultKey.GenerateVaultKey();
                    //StoreKey.GenKey_SaveInContainer("MyKeyContainer");
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
    }
}
