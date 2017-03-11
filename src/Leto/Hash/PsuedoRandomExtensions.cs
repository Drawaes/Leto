using Leto.Hash;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Hash
{
    public static class PsuedoRandomExtensions
    {
        //https://tools.ietf.org/html/rfc5246#section-4.7
        //TLS 1.2 Secret Expansion into an n length run of bytes
        public static void Tls12(this IHashProvider hashProvider, HashType hashType, Span<byte> keyMaterial, Span<byte> secret, Span<byte> label, Span<byte> seed)
        {
            var hashSize = hashProvider.HashSize(hashType);
            var a1Length = hashSize + seed.Length + label.Length;
            var a1 = new byte[a1Length];
            label.CopyTo(a1.Slice(hashSize));
            seed.CopyTo(a1.Slice(hashSize + label.Length));
            var seedSpan = a1.Slice(hashSize);
            hashProvider.HmacData(hashType, secret, seedSpan, a1.Slice(0, hashSize));
            Tls12Expansion(hashProvider, hashType, hashSize, a1, keyMaterial, secret);
        }

        private static void Tls12Expansion(IHashProvider hash, HashType hashType, int hashSize, Span<byte> a1, Span<byte> keyMaterial, Span<byte> secret)
        {
            var currentKeyData = new byte[hashSize];
            int keyMaterialIndex = 0;
            while (true)
            {
                hash.HmacData(hashType, secret, a1, currentKeyData);
                for (var i = 0; i < hashSize; i++)
                {
                    keyMaterial[keyMaterialIndex] = currentKeyData[i];
                    keyMaterialIndex++;
                    if (keyMaterialIndex == keyMaterial.Length)
                    {
                        return;
                    }
                }
                hash.HmacData(hashType, secret, a1.Slice(0, hashSize), a1.Slice(0, hashSize));
            }
        }
    }
}
