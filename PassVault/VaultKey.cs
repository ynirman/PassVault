using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;

namespace PassVault
{
    public static class VaultKey
    {
        const int VAULT_KEY_BYTES = 16;
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

        // Generating 128 random bits with CSPRNG
        public static byte[] GenerateVaultKey()
        {
            byte[] vaultKey = new byte[VAULT_KEY_BYTES];
            rngCsp.GetBytes(vaultKey);

            return vaultKey;
        }
    }
}
