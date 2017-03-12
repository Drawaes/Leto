using System;

namespace Leto.Hashes
{
    public static class PsuedoRandomExtensions
    {
        //https://tools.ietf.org/html/rfc5246#section-4.7
        //TLS 1.2 Secret Expansion into an n length run of bytes
        // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
        //                     HMAC_hash(secret, A(2) + seed) +
        //                     HMAC_hash(secret, A(3) + seed) + ...
        // A() is defined as:
        // A(0) = seed
        // A(i) = HMAC_hash(secret, A(i-1))
        public static void Tls12Prf(this IHashProvider hashProvider, HashType hashType, Span<byte> secret, Span<byte> label, Span<byte> seed, Span<byte> keyMaterial)
        {
            var hashSize = hashProvider.HashSize(hashType);
            var aLength = hashSize + seed.Length + label.Length;
            var a = new byte[aLength];
            label.CopyTo(a.Slice(hashSize));
            seed.CopyTo(a.Slice(hashSize + label.Length));
            hashProvider.HmacData(hashType, secret, a.Slice(hashSize), a);
            
            var currentKeyData = new byte[hashSize];
            while (keyMaterial.Length > 0)
            {
                //HMAC_hash(secret, A(n) + seed)
                hashProvider.HmacData(hashType, secret, a, currentKeyData);
                //Copy required bytes into the output keymaterial and reduce size remaining
                int amountToCopy = Math.Min(keyMaterial.Length, currentKeyData.Length);
                currentKeyData.Slice(0, amountToCopy).CopyTo(keyMaterial);
                keyMaterial = keyMaterial.Slice(amountToCopy);
                //A(n) = HMAC_hash(secret, A(n-1))
                hashProvider.HmacData(hashType, secret, a.Slice(0, hashSize), a);
            }
        }
    }
}
