using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace PassVault
{
    // Key-Value pair stored in registry, encrypted with DPAPI
    public static class DataStore
    {
        public static void SaveData(string key, byte[] toEncrypt, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            RegistryKey registry = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\PassVault");

            string data = Convert.ToBase64String(ProtectedData.Protect(toEncrypt, null, scope));
            registry.SetValue(key, data);
            registry.Close();
        }

        public static byte[] GetData(string key, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            RegistryKey registry = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\PassVault");

            string encryptedData64 = (string)registry.GetValue(key);
            byte[] encryptedData = Convert.FromBase64String(encryptedData64);

            //string data = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(encryptedData), null, scope));
            byte[] decryptedData = ProtectedData.Unprotect(encryptedData, null, scope);
            registry.Close();

            return decryptedData;
        }
    }
}
