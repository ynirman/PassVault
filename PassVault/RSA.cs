using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace PassVault
{
    class RSA
    {
        const int KEY_SIZE_IN_BYTES = 16;
        private RNGCryptoServiceProvider rngCsp;

        public RSA()
        {
            rngCsp = new RNGCryptoServiceProvider();
        } 

        //Generates a large number. 
        public BigInteger GenerateLargeNumber(BigInteger bottom, BigInteger top)
        {
            BigInteger largeNum, result;
            
            byte[] randomNumber = new byte[32];
            rngCsp.GetBytes(randomNumber);            
            largeNum = new BigInteger(randomNumber);
            largeNum = BigInteger.Abs(largeNum);
            result = bottom + (largeNum % (top - bottom + 1));

            return result;         
        }


        public bool isPrime(BigInteger largeNum)
        {
            if (largeNum == 2) return true;
            if ((largeNum & 1) == 0) return false; // is odd

            return MillerRabin(largeNum, 20);
        }

        public bool MillerRabin(BigInteger largeNum, int rounds)
        {
            BigInteger d, r;
            bool isPrime = true;
            
            // find d and r that r is odd and largeNum - 1 = 2^d * r
            for (d = 0, r = largeNum - 1; r.IsEven; d++, r >>= 1) ;

            for (int i = 0; i < rounds && isPrime == true; i++)
            {
                isPrime = MillerRabinTest(largeNum, this.GenerateLargeNumber(2, largeNum - 2), r, d);
            }
            return isPrime;

        }

        public bool MillerRabinTest(BigInteger largeNum, BigInteger a, BigInteger r, BigInteger d)
        {
            BigInteger x = BigInteger.ModPow(a, r, largeNum);
            
            if (x == 1 || x == largeNum - 1) return true;
            
            for (int i = 1; i < d; i++)
            {
                x = BigInteger.ModPow(x, 2, largeNum);
                if (x == 1) return false;
                if (x == largeNum - 1) return true;
            }
            return false;
        }

        public byte[] Encrypt(byte[] text)
        {
            return null;
        }

    }
}
