using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;

/// <summary>
///  AES algorithm implemented from scratch
///  Confusion, Diffusion and secrecy only in the key!
///  Example use: 
///  AES.StartAES(Encoding.ASCII.GetBytes(plaintext),
///               AES,AES_Type.Encrypt);
/// </summary>
namespace PassVault
{
    public static class AES
    {
        public enum AES_Type { Encrypt, Decrypt };
        const int KEY_SIZE_IN_BYTES = 16;
        const int BLOCK_SIZE_IN_BYTES = 16;
        const int NUM_MAIN_ROUNDS = 9;
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        static AES_Type cipherType; // Encrypt or Decrypt

        public static byte[] StartAES(byte[] plaintext, AES_Type type)
        {
            cipherType = type;
            // TODO get vaultKey 128bits instead of hardcoded
            byte[] vaultKey = new byte[KEY_SIZE_IN_BYTES];
            rngCsp.GetBytes(vaultKey);
            vaultKey = Encoding.ASCII.GetBytes("abcdefghidsjklmnop");

            // At the first iteration, keyMatrix is our vaultKey
            byte[,] keyMatrix = ByteBlockToMatrix(vaultKey);
            Utils.PadToBlockSize(ref plaintext, 16);
            int numberOfBlocks = plaintext.Length / BLOCK_SIZE_IN_BYTES;
            byte[] cypheredText = new byte[16 * numberOfBlocks];

            // ForEach Block
            for (int i = 0; i < numberOfBlocks; i++)
            {
                // Set plaintext block as stateMatrix
                byte[] currentBlock = new byte[16];
                Buffer.BlockCopy(plaintext, i * 16, currentBlock, 0, 16);
                byte[,] stateMatrix = ByteBlockToMatrix(currentBlock);

                if (cipherType == AES_Type.Encrypt)
                    Encryption(stateMatrix, keyMatrix);
                else
                    Decryption(stateMatrix, keyMatrix);

                // Apppend current cyphered block
                byte[] cypheredBlock = MatrixToByteBlock(stateMatrix);
                Buffer.BlockCopy(cypheredBlock, 0, cypheredText, i * 16, 16);
            }
            return cypheredText;
        }

        public static void Encryption(byte[,] stateMatrix, byte[,] keyMatrix)
        {
            byte[] derivedRoundKeys = MyHKDF.KeyDerivation(16, MatrixToByteBlock(keyMatrix), 10);
            // Initial round
            AddRoundKey(stateMatrix, keyMatrix);
            // 9 main rounds (depends on key length) of substitution and permutation
            for (int i = 1; i <= NUM_MAIN_ROUNDS;  i++)
            {
                byte[,] roundKey = GetCurrentRoundKey(derivedRoundKeys, i);
                SubBytes(stateMatrix);
                ShiftRows(stateMatrix);
                MixColumns(stateMatrix);
                AddRoundKey(stateMatrix, roundKey);
            }
            // Final round
            SubBytes(stateMatrix);
            ShiftRows(stateMatrix);
            AddRoundKey(stateMatrix, GetCurrentRoundKey(derivedRoundKeys, 10));
        }

        public static void Decryption(byte[,] stateMatrix, byte[,] keyMatrix)
        {
            byte[] derivedRoundKeys = MyHKDF.KeyDerivation(16, MatrixToByteBlock(keyMatrix), 10);
            // Initial round
            AddRoundKey(stateMatrix, GetCurrentRoundKey(derivedRoundKeys, 10));
            ShiftRows(stateMatrix);
            SubBytes(stateMatrix);
            // 9 main rounds (depends on key length) of substitution and permutation
            for (int i = 1; i <= NUM_MAIN_ROUNDS; i++)
            {
                byte[,] roundKey = GetCurrentRoundKey(derivedRoundKeys, NUM_MAIN_ROUNDS - i + 1);
                AddRoundKey(stateMatrix, roundKey);
                MixColumns(stateMatrix);
                ShiftRows(stateMatrix);
                SubBytes(stateMatrix);
            }
            // Final round
            AddRoundKey(stateMatrix, keyMatrix);
        }

        // XORing state with current key
        public static void AddRoundKey(byte[,] stateMatrix, byte[,] keyMatrix)
        {
            for (int i = 0; i < stateMatrix.GetLength(0); i++)
            {
                for (int j = 0; j < stateMatrix.GetLength(1); j++)
                {
                    stateMatrix[i, j] = (byte)(stateMatrix[i, j] ^ keyMatrix[i, j]);
                }
            }
        }
        public static byte[,] GetCurrentRoundKey(byte[] derivedKeys, int currentRound)
        {
            byte[] currentRoundKey = new byte[16];
            Buffer.BlockCopy(derivedKeys, (currentRound - 1) * 16, currentRoundKey, 0, 16);

            return ByteBlockToMatrix(currentRoundKey);
        }

        // Substitute stateMatrix bytes based on sbox
        public static void SubBytes(byte[,] stateMatrix)
        {
            for (int i = 0; i < stateMatrix.GetLength(0); i++)
            {
                for (int j = 0; j < stateMatrix.GetLength(1); j++)
                {
                    // Split byte into row and column
                    string byteAsString = Convert.ToString(stateMatrix[i, j], 2);
                    string paddedByteAsString = byteAsString.PadLeft(8, '0');
                    int rowFromByte = Convert.ToInt32(paddedByteAsString.Substring(0, 4), 2);
                    int colFromByte = Convert.ToInt32(paddedByteAsString.Substring(4, 4), 2);
                    // Lookup in a pre defined substitution box
                    if (cipherType == AES_Type.Encrypt)
                        stateMatrix[i, j] = Utils.sbox[rowFromByte, colFromByte];
                    else
                        stateMatrix[i, j] = Utils.sboxInverse[rowFromByte, colFromByte];
                }
            }
        }

        // Cyclically shifts bytes in each row with an increasing offset 
        public static void ShiftRows(byte[,] stateMatrix)
        {
            int length = stateMatrix.GetLength(0);
            for (int i = 1; i < length; i++)
            {
                byte[] temp = new byte[4];
                // Set up shifted rows inside temp
                if (cipherType == AES_Type.Encrypt)
                {
                    for (int j = 0; j < length; j++)
                    {
                        if (j - i >= 0)
                            temp[j - i] = stateMatrix[i, j];
                        // overflows
                        else
                            temp[length - i + j] = stateMatrix[i, j];
                    }
                }
                else
                {
                    for (int j = 0; j < length; j++)
                    {
                        if (j + i < length)
                            temp[j + i] = stateMatrix[i, j];
                        // overflows
                        else
                            temp[(i + j) % length] = stateMatrix[i, j];

                    }
                }
                // Copy Shifted rows from Temp to stateMatrix
                for (int k = 0; k < length; k++)
                {
                    stateMatrix[i, k] = temp[k];
                }
            }
        }

        // Diffusion by column multiplication in GF field
        public static void MixColumns(byte[,] stateMatrix)
        {
            byte[,] temp = new byte[4, 4];
            // ForEach Column
            if (cipherType == AES_Type.Encrypt)
                for (int i = 0; i < stateMatrix.GetLength(1); i++)
                {
                    temp[0, i] = (byte)((BytesMultiplication(0x02, stateMatrix[0, i]) ^ BytesMultiplication(0x03, stateMatrix[1, i]) ^ stateMatrix[2, i] ^ stateMatrix[3, i]));
                    temp[1, i] = (byte)((stateMatrix[0, i] ^ BytesMultiplication(0x02, stateMatrix[1, i]) ^ BytesMultiplication(0x03, stateMatrix[2, i]) ^ stateMatrix[3, i]));
                    temp[2, i] = (byte)((stateMatrix[0, i] ^ stateMatrix[1, i] ^ BytesMultiplication(0x02, stateMatrix[2, i]) ^ BytesMultiplication(0x03, stateMatrix[3, i])));
                    temp[3, i] = (byte)((BytesMultiplication(0x03, stateMatrix[0, i]) ^ stateMatrix[1, i] ^ stateMatrix[2, i] ^ BytesMultiplication(0x02, stateMatrix[3, i])));
                }
            else
                for (int i = 0; i < stateMatrix.GetLength(1); i++)
                {
                    temp[0, i] = (byte)((BytesMultiplication(0x0E, stateMatrix[0, i])) ^ (BytesMultiplication(0x0B, stateMatrix[1, i]))
                                ^ (BytesMultiplication(0x0D, stateMatrix[2, i])) ^ (BytesMultiplication(0x09, stateMatrix[3, i])));
                    temp[1, i] = (byte)((BytesMultiplication(0x09, stateMatrix[0, i])) ^ (BytesMultiplication(0x0E, stateMatrix[1, i]))
                                ^ (BytesMultiplication(0x0B, stateMatrix[2, i])) ^ (BytesMultiplication(0x0D, stateMatrix[3, i])));
                    temp[2, i] = (byte)((BytesMultiplication(0x0D, stateMatrix[0, i])) ^ (BytesMultiplication(0x09, stateMatrix[1, i]))
                                ^ (BytesMultiplication(0x0E, stateMatrix[2, i])) ^ (BytesMultiplication(0x0B, stateMatrix[3, i])));
                    temp[3, i] = (byte)((BytesMultiplication(0x0B, stateMatrix[0, i])) ^ (BytesMultiplication(0x0D, stateMatrix[1, i]))
                                ^ (BytesMultiplication(0x09, stateMatrix[2, i])) ^ (BytesMultiplication(0x0E, stateMatrix[3, i])));
                }
            Utils.CopyMatrix(temp, stateMatrix);
        }

        // Converting plaintext to an array of bytes
        public static byte[] PlaintextToBytes(string plaintext)
        {
            byte[] plaintextInBytes = Encoding.ASCII.GetBytes(plaintext);
            Utils.PadToBlockSize(ref plaintextInBytes, BLOCK_SIZE_IN_BYTES);

            return plaintextInBytes;
        }

        // Converting an array of bytes to a matrix
        public static byte[,] ByteBlockToMatrix(byte[] block)
        {
            byte[,] matrix = new byte[4, 4];
            int keyByteCount = 0;
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    matrix[i, j] = block[keyByteCount];
                    keyByteCount++;
                }
            }

            return matrix;
        }

        public static byte[] MatrixToByteBlock(byte[,] matrix)
        {
            byte[] block = new byte[16];
            int keyByteCount = 0;
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    block[keyByteCount] = matrix[i, j];
                    keyByteCount++;
                }
            }

            return block;
        }

        public static byte BytesMultiplication(byte a, byte b)
        {
            byte p = 0;
            for (int counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }
                bool high_bit_set = (a & 0x80) != 0;
                a <<= 1;
                if (high_bit_set)
                {
                    a ^= 0x1B;
                }
                b >>= 1;
            }

            return p;
        }
    }
}

