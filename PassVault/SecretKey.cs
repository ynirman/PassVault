﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;

namespace PassVault
{
    public static class SecretKey
    {
        const int SECRET_KEY_LENGTH = 26;
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        
        // Generating 26 length string of random characters for the Secret Key
        public static SecureString GenerateSecretKey(string username)
        {
            Dictionary<double, char> numberToCharacter = Utils.numberToCharacter;
            StringBuilder secretKey = new StringBuilder();
            for(int i=0; i < SECRET_KEY_LENGTH; i++)
            {
                byte[] randomNumber = new byte[8];
                rngCsp.GetBytes(randomNumber);
                double generatedNumber = Math.Abs((BitConverter.ToInt32(randomNumber, 0) % 31));

                if (numberToCharacter.ContainsKey(generatedNumber))
                {
                    secretKey.Append(numberToCharacter[generatedNumber]);
                }
                else
                {
                    throw new Exception("Value not found in dictionary.");
                }
            }

            return secretKey.ToString();
        }
    }
}
