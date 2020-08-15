using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

namespace PassVault
{
    // Slow password hashing
    public static class PBKDF2
    {
        const int HASHING_ITERATIONS = 100000;
        const int OUTPUT_LENGTH_IN_BYTES = 32;

        public static byte[] PerformPBKDF(byte[] masterPassword, byte[] salt)
        {
            // Preprocessing
            byte[] producedSalt = HandleSalt(salt);
            byte[] normalizedMasterPassword = HandleMasterPassword(masterPassword);

            byte[] calculatedHash = new byte[OUTPUT_LENGTH_IN_BYTES];
            Buffer.BlockCopy(producedSalt, 0, calculatedHash, 0, OUTPUT_LENGTH_IN_BYTES);

            for (int i = 0; i < HASHING_ITERATIONS; i++)
            {
                calculatedHash = HMAC_SHA256(normalizedMasterPassword, calculatedHash);
                //Debug.WriteLine(i + " " + Encoding.ASCII.GetString(calculatedHash));
            }

            return calculatedHash;
        }
        private static byte[] HMAC_SHA256(byte[] key, byte[] message)
        {
            var hash = new HMACSHA256(key);
            return hash.ComputeHash(message);
        }

        private static byte[] HandleSalt(byte[] salt)
        {
            if (salt.Length == OUTPUT_LENGTH_IN_BYTES)
            {
                return salt;
            }
            else
            {
                return MyHKDF.KeyExpansion(OUTPUT_LENGTH_IN_BYTES, salt);
            }
        }

        private static byte[] HandleMasterPassword(byte[] masterPassword)
        {
            string stringPassword = Encoding.ASCII.GetString(masterPassword);
            string processedStringPassword = stringPassword.Normalize().Trim();

            return Encoding.ASCII.GetBytes(processedStringPassword);
        }
    }
}
