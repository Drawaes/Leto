using System;

namespace Leto.Hashes
{
    public static class PsuedoRandomExtensions
    {
        private static readonly byte[] s_empty = new byte[1024 / 8];
        private const int HkdfLabelHeaderSize = 4;

        //https://tools.ietf.org/html/rfc5246#section-4.7
        //TLS 1.2 Secret Expansion into an n length run of bytes
        // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
        //                     HMAC_hash(secret, A(2) + seed) +
        // A() is defined as:
        // A(0) = seed
        // A(i) = HMAC_hash(secret, A(i-1))
        public static void Tls12Prf(this IHashProvider hashProvider, HashType hashType, Span<byte> secret, Span<byte> label, Span<byte> seed, Span<byte> keyMaterial)
        {
            var hashSize = hashProvider.HashSize(hashType);
            var aLength = hashSize + seed.Length + label.Length;
            var a1 = new byte[aLength];
            label.CopyTo(a1.Slice(hashSize));
            seed.CopyTo(a1.Slice(hashSize + label.Length));
            hashProvider.HmacData(hashType, secret, a1.Slice(hashSize), a1);

            var currentKeyData = new byte[hashSize];
            while (keyMaterial.Length > 0)
            {
                //HMAC_hash(secret, A(n) + seed)
                hashProvider.HmacData(hashType, secret, a1, currentKeyData);
                //Copy required bytes into the output keymaterial and reduce size remaining
                int amountToCopy = Math.Min(keyMaterial.Length, currentKeyData.Length);
                currentKeyData.Slice(0, amountToCopy).CopyTo(keyMaterial);
                keyMaterial = keyMaterial.Slice(amountToCopy);
                //A(n) = HMAC_hash(secret, A(n-1))
                hashProvider.HmacData(hashType, secret, a1.Slice(0, hashSize), a1);
            }
        }

        //https://tools.ietf.org/html/rfc5869
        public static void HkdfExtract(IHashProvider provider, HashType hashType, Span<byte> salt, Span<byte> ikm, Span<byte> output)
        {
            if (salt.Length == 0)
            {
                salt = s_empty.Slice(0, provider.HashSize(hashType));
            }
            if (ikm.Length == 0)
            {
                ikm = s_empty.Slice(0, provider.HashSize(hashType));
            }
            provider.HmacData(hashType, salt, ikm, output);
        }

        //https://tools.ietf.org/html/rfc5869
        public static void HkdfExpand(IHashProvider provider, HashType hashType, Span<byte> prk, Span<byte> info, Span<byte> output)
        {
            int hashLength = provider.HashSize(hashType);
            var tLength = hashLength + info.Length + sizeof(byte);
            var t = new byte[tLength];
            info.CopyTo(t.Slice(hashLength));

            byte counter = 1;
            var counterSpan = t.Slice(t.Length - 1);
            counterSpan.Write(counter);
            provider.HmacData(hashType, prk, t.Slice(hashLength), t.Slice(0,hashLength));
            while (true)
            {
                int amountToCopy = Math.Min(hashLength, output.Length);
                t.Slice(0, amountToCopy).CopyTo(output);
                output = output.Slice(amountToCopy);
                if (output.Length == 0) return;
                counter++;
                counterSpan.Write(counter);
                provider.HmacData(hashType, prk, t, t.Slice(0,hashLength));
            }
        }

    }
}
