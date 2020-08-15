using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace PassVault
{
    class Vault
    {
        private string username;
        private byte[] vaultKey;
        private List<VaultEntry> vaultList;
        private List<string> services;

        public Vault(string username, byte[] vaultKey)
        {
            this.username = username;
            this.vaultKey = vaultKey;
            this.services = LoadServices();
            vaultList = new List<VaultEntry>();
            LoadVault();
        }

        private void LoadVault()
        {

            if (services == null) return;
            foreach (string service in services)
            {
                byte[] encryptedPassword = DataStore.GetData(service);
                string decryptedPassword = Encoding.ASCII.GetString(AES.StartAES(encryptedPassword, AES.AES_Type.Decrypt, vaultKey)).TrimEnd('\0');
                vaultList.Add(new VaultEntry()
                {
                    Service = service,
                    Password = decryptedPassword
                });
            }
        }

        private List<string> LoadServices()
        {
            if (DataStore.IsExists(Globals.SERVICES))
            {
                byte[] servicesByteArray = AES.StartAES(DataStore.GetData(Globals.SERVICES), AES.AES_Type.Decrypt, vaultKey);
                string servicesString = Encoding.ASCII.GetString(servicesByteArray);
                return servicesString.Split('|').Select(s => s.TrimEnd('\0')).ToList();
            }
            return null;
        }

        private void AddServiceName(string servicename)
        {
            if (services == null)
            {
                services = new List<string>() { servicename };
                byte[] encryptedService = AES.StartAES(Encoding.ASCII.GetBytes(servicename), AES.AES_Type.Encrypt, vaultKey);
                DataStore.SaveData(Globals.SERVICES, encryptedService);
            }
            else if (!services.Contains(servicename))
            {
                this.services.Add(servicename);
                string servicesString = String.Join('|', this.services);
                byte[] encryptedServices = AES.StartAES(Encoding.ASCII.GetBytes(servicesString), AES.AES_Type.Encrypt, vaultKey);
                DataStore.SaveData(Globals.SERVICES, encryptedServices);
            }
        }

        public void AddService(string servicename, string password)
        {
            AddServiceName(servicename);
            byte[] encryptedPassword = AES.StartAES(Encoding.ASCII.GetBytes(password), AES.AES_Type.Encrypt, vaultKey);
            DataStore.SaveData(servicename, encryptedPassword);
            vaultList.Add(new VaultEntry()
            {
                Service = servicename,
                Password = password
            });
        }

        public List<VaultEntry> GetVault()
        {
            return vaultList;
        }



    }
}
