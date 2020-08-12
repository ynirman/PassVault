using SecurityDriven.Inferno.Extensions;
using SecurityDriven.Inferno.Kdf;
using SecurityDriven.Inferno.Mac;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PassVault
{
    // extracting pseudo random keys and expanding\deriving
    public static class MyHKDF
    {
        public static byte[] KeyExpansion(int expandToLength, byte[] keyToExpand, string additionalData)
        {
            HashAlgorithmName algorithm = HashAlgorithmName.SHA256;
            using (var hkdf = new HKDF(HMACFactories.HMACSHA256, keyToExpand, additionalData.ToBytes()))
            {
                return hkdf.GetBytes(expandToLength);
            }
        }

        public static byte[] KeyDerivation(int keyLengthInBytes, byte[] keyToExpand, int numberOfKeysToDerive)
        {
            HashAlgorithmName algorithm = HashAlgorithmName.SHA256;
            using (var hkdf = new HKDF(HMACFactories.HMACSHA256, keyToExpand))
            {
                return hkdf.GetBytes(keyLengthInBytes * numberOfKeysToDerive);
            }
        }
    }
}
