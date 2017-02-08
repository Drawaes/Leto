using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Hash;

namespace Leto.Tls13.KeyExchange
{
    public class PrfFunctions
    {
        public static unsafe void P_Hash12(IHashProvider hash, HashType hashType, Span<byte> keyMaterial, void* secret, int secretLength, Span<byte> seed)
        {
            var hashSize = hash.HashSize(hashType);
            var a1Length = hashSize + seed.Length;
            var a1 = stackalloc byte[a1Length];
            Span<byte> a1Span = new Span<byte>(a1, a1Length);
            seed.CopyTo(a1Span.Slice(hashSize));
            var seedPtr = a1 + hashSize;
            hash.HmacData(hashType, secret, secretLength, seedPtr, seed.Length, a1, hashSize);
            var currentKeyData = stackalloc byte[hashSize];

            int keyMaterialIndex = 0;
            while (true)
            {
                hash.HmacData(hashType, secret, secretLength, a1, a1Length, currentKeyData, hashSize);
                for (int i = 0; i < hashSize; i++)
                {
                    keyMaterial[keyMaterialIndex] = currentKeyData[i];
                    keyMaterialIndex++;
                    if (keyMaterialIndex == keyMaterial.Length)
                    {
                        return;
                    }
                }
                hash.HmacData(hashType, secret, secretLength, a1, hashSize, a1, hashSize);
            }
        }
    }
}
