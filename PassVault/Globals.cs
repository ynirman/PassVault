using System;
using System.Collections.Generic;
using System.Text;

namespace PassVault
{
    public static class Globals
    {
        public const string Salt = "Salt";
        public const string SecretKey = "SecretKey";
        public const string VaultKey = "VaultKey";
        public const string MasterUnlockKey = "MUK";
        public const string RSAPublicKey = "RSAPublicKey";
        public const string RSAPrivateKey = "RSAPrivateKey";
        public const string EncryptionVerifier = "EncryptionVerifier"; // Should be some secret, that changes ragulary.
        public const string RSANumber = "RSANumber";
        public const string SERVICES = "Services";
    }
}
