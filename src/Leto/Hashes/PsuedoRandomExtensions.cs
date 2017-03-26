using System;
using System.Binary;

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
        public static void Tls12Prf(this IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed, Span<byte> keyMaterial)
        {
            var hashSize = hashProvider.HashSize(hashType);
            var aLength = hashSize + seed.Length + label.Length;
            var a1 = new byte[aLength];
            label.CopyTo(a1.Slice(hashSize));
            seed.CopyTo(a1.Slice(hashSize + label.Length));
            hashProvider.HmacData(hashType, secret, a1.Slice(hashSize), a1.Slice(0,hashSize));

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
                hashProvider.HmacData(hashType, secret, a1.Slice(0, hashSize), a1.Slice(0,hashSize));
            }
        }

        //https://tools.ietf.org/html/rfc5869
        public static void HkdfExtract(this IHashProvider provider, HashType hashType, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> ikm, Span<byte> output)
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
        public static void HkdfExpand(this IHashProvider provider, HashType hashType, ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, Span<byte> output)
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

        //https://tlswg.github.io/tls13-spec/#key-schedule
        //HKDF-Expand-Label(Secret, Label, HashValue, Length) =
        //HKDF-Expand(Secret, HkdfLabel, Length)
        //Where HkdfLabel is specified as:
        //struct {
        //uint16 length = Length;
        //opaque label<10..255> = "TLS 1.3, " + Label;
        //opaque hash_value<0..255> = HashValue;
        //}
        //HkdfLabel;
        public static void HkdfExpandLabel(this IHashProvider provider, HashType hashType, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> hash, Span<byte> output)
        {
            var hkdfSize = HkdfLabelHeaderSize + label.Length + hash.Length;
            var hkdfLabel = new byte[hkdfSize];
            
            var hkdfSpan = hkdfLabel.WriteBigEndian((ushort)output.Length);
            hkdfSpan = hkdfSpan.WriteBigEndian((byte)label.Length);
            label.CopyTo(hkdfSpan);
            hkdfSpan = hkdfSpan.Slice(label.Length);
            hkdfSpan = hkdfSpan.WriteBigEndian((byte)hash.Length);
            hash.CopyTo(hkdfSpan);
            
            HkdfExpand(provider, hashType, secret, hkdfLabel, output);
        }
    }
}
