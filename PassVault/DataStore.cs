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
        public static void SaveData(string key, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            RegistryKey registry = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\PassVault");

            registry.SetValue(key, "");
            registry.Close();
        }
        public static void SaveData(string key, byte[] toEncrypt, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            string username = UserLogin.username;
            RegistryKey registry = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\PassVault");

            string data = Convert.ToBase64String(ProtectedData.Protect(toEncrypt, null, scope));
            registry.SetValue(username + "-" + key, data);
            registry.Close();
        }

        public static byte[] GetData(string key, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            string username = UserLogin.username;
            RegistryKey registry = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\PassVault");

            string encryptedData64 = (string)registry.GetValue(username + "-" + key);
            byte[] encryptedData = Convert.FromBase64String(encryptedData64);

            //string data = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(encryptedData), null, scope));
            byte[] decryptedData = ProtectedData.Unprotect(encryptedData, null, scope);
            registry.Close();

            return decryptedData;
        }

        public static bool IsExists(string key, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            RegistryKey registry = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\PassVault");
            try
            {
                if (registry.GetValue(key) != null)
                    return true;
                else return false;
            }
            catch
            {
                return false;
            }
        }
    }
}
