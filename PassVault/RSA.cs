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
        BigInteger p, q, n, phi, e, d;

        public RSA()
        {
            rngCsp = new RNGCryptoServiceProvider();

            // Choose two distinct prime numbers p and q.
            p = NearestPrime(GenerateLargeNumber());
            q = NearestPrime(GenerateLargeNumber());

            n = p * q;
            phi = (p - 1) * (q - 1);

            e = NearestPrime(GenerateLargeNumber(2, phi));
            d = ExtendedEuclideanAlgorithm(phi, e);
            if (d < 0) d = d + phi; // if we got a negative
        } 

        public Tuple<BigInteger, BigInteger> getPublicKey()
        {
            return new Tuple<BigInteger,BigInteger>(e, n);
        }

        public Tuple<BigInteger, BigInteger> getPrivateKey()
        {
            return new Tuple<BigInteger, BigInteger>(d, n);
        }

        public BigInteger ExtendedEuclideanAlgorithm(BigInteger a, BigInteger b)
        {
            BigInteger y1 = 1, y2 = 0;
            while (b > 0)
            {
                BigInteger div = a / b;
                
                BigInteger temp = y1;
                y1 = y2 - div * y1;
                y2 = temp;
                
                BigInteger r = a % b;
                a = b;
                b = r;
            }
            return y2;
        }

        public BigInteger NearestPrime(BigInteger num)
        {
            while(!isPrime(num))
            {
                num--;
            }
            return num;
        }

        //Generates a large number x that bottom <= x <= top. 
        public BigInteger GenerateLargeNumber(BigInteger bottom, BigInteger top)
        {
            BigInteger largeNum = GenerateLargeNumber(), result;
            result = bottom + (largeNum % (top - bottom + 1));

            return result;         
        }

        //Generates a large number. 
        public BigInteger GenerateLargeNumber()
        {
            BigInteger largeNum;

            byte[] randomNumber = new byte[128];
            rngCsp.GetBytes(randomNumber);
            largeNum = new BigInteger(randomNumber);
            //Debug.WriteLine(largeNum.ToString().Length);
            return BigInteger.Abs(largeNum);
        }


        public bool isPrime(BigInteger largeNum)
        {
            if (largeNum == 2) return true;
            if ((largeNum & 1) == 0) return false; // is odd

            return MillerRabin(largeNum, 40);
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

        public byte[] Encrypt(byte[] plainText)
        {
            BigInteger bytesToInt = new BigInteger(plainText);
            return BigInteger.ModPow(bytesToInt, e, n).ToByteArray();
        }

        public byte[] Encrypt(byte[] plainText, Tuple<BigInteger,BigInteger> publicKey)
        {
            BigInteger bytesToInt = new BigInteger(plainText);
            return BigInteger.ModPow(bytesToInt, publicKey.Item1, publicKey.Item2).ToByteArray();
        }

        public byte[] Decrypt(byte[] cipher)
        {
            BigInteger bytesToInt = new BigInteger(cipher);
            return BigInteger.ModPow(bytesToInt, d, n).ToByteArray();
        }

        public byte[] Decrypt(byte[] cipher, Tuple<BigInteger, BigInteger> privateKey)
        {
            BigInteger bytesToInt = new BigInteger(cipher);
            return BigInteger.ModPow(bytesToInt, privateKey.Item1, privateKey.Item2).ToByteArray();
        }
    }
}
