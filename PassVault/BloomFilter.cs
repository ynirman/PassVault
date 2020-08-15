using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace PassVault
{
    class BloomFilter
    {
        private const int NUMBER_OF_ITEMS = 1000000;
        //private const string PATH_TO_ITEMS = @"C:\Users\nirman\source\repos\PassVault\PassVault\top1000000";
        private float fp; // False-Positive rate.
        private int m; // Size of bit array.
        private int k; // Number of hash functions we will use.
        private BitArray bloomFilter; // The bit array that represents the filter.

        public BloomFilter(float falsePositive)
        {
            this.fp = falsePositive;
            this.m = (int)(-NUMBER_OF_ITEMS * Math.Log(fp) / Math.Pow(Math.Log(2), 2)); 
            this.bloomFilter = new BitArray(m);
            this.k = (int)(m * Math.Log(2) / NUMBER_OF_ITEMS);
            this.InitFilter();
        }

        // Initialize the bit array from our bad passwords file(Top 1,000,000 bad passwords by SecLists)
        private void InitFilter()
        {
            string pathToBloomBin = Directory.GetCurrentDirectory() + "\\top1000000.bin";
            //using (var fileStream = File.OpenRead(pathToFile))
            //{
            //    using (var streamReader = new StreamReader(fileStream))
            //    {
            //        String password;
            //        while ((password = streamReader.ReadLine()) != null)
            //        {
            //            for (int i = 1; i <= k; i++)
            //            {
            //                using (HMACSHA256 hmac = new HMACSHA256(BitConverter.GetBytes(i)))
            //                {
            //                    var hashedPass = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            //                    int index = (int)(BitConverter.ToUInt32(hashedPass) % m);
            //                    bloomFilter[index] = true;                              
            //                }
            //            }
            //        }
            //    }
            //}
            //int bytesNumber = m / 8;
            //if (bytesNumber % 8 != 0) bytesNumber++;
            //byte[] bitToByte = new byte[bytesNumber];
            //bloomFilter.CopyTo(bitToByte, 0);
            //File.WriteAllBytes(pathToFile + ".bin", bitToByte);

            byte[] byteToBit = File.ReadAllBytes(pathToBloomBin + ".bin");
            this.bloomFilter = new BitArray(byteToBit);
            
            //bool a = CountTrue(newBloomFilter) == CountTrue(bloomFilter);
            //int min = Math.Min(newBloomFilter.Count, bloomFilter.Count);
            //for (int i = 0; i < min; i++)
            //{
            //    if (bloomFilter[i] != newBloomFilter[i])
            //    {
            //        Debug.WriteLine("BIG BUGG!!!");
            //    }
            //}

            //Debug.WriteLine("The compare: " + a.ToString());
            
        }

        // Returns true if a given string was found in our filter with false positive rate - fp.
        // Returns false if a string was not found(without mistakes).
        public bool Find(string password)
        {
            for (int i = 1; i <= k; i++)
            {
                using (HMACSHA256 hmac = new HMACSHA256(BitConverter.GetBytes(i)))
                {
                    var hashedPass = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                    int index = (int)(BitConverter.ToUInt32(hashedPass) % m);
                    if (bloomFilter[index] == false)
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        private int CountTrue(BitArray bf)
        {
            int counter = 0;
            foreach (var i in bf)
            {
                if ((bool)i) counter++;
            }
            return counter;
        }

    }
}
