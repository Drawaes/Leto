using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Leto.Tls13.Hash;
using Leto.Tls13.Internal;

namespace Leto.Tls13.KeyExchange
{
    public static class HkdfFunctions
    {
        private static readonly IntPtr s_zeroArray;
        private const int HkdfLabelHeaderSize = 4;

        static HkdfFunctions()
        {
            var emptyArray = new byte[1024 / 8];
            s_zeroArray = Marshal.AllocHGlobal(emptyArray.Length);
            Marshal.Copy(emptyArray, 0, s_zeroArray, emptyArray.Length);
        }

        public static unsafe void HkdfExtract(IHashProvider provider, HashType hashType, void* salt, int saltLength, void* ikm, int ikmLength, void* output, int outputLength)
        {
            if (saltLength == 0)
            {
                salt = (byte*)s_zeroArray;
                saltLength = provider.HashSize(hashType);
            }
            if (ikmLength == 0)
            {
                ikm = (byte*)s_zeroArray;
                ikmLength = provider.HashSize(hashType);
            }
            provider.HmacData(hashType, salt, saltLength, ikm, ikmLength, output, outputLength);
        }

        public static unsafe void HkdfExpand(IHashProvider provider, HashType hashType, void* prk, int prkLength, Span<byte> info, Span<byte> output)
        {
            int hashLength = provider.HashSize(hashType);
            var tLength = hashLength + info.Length + sizeof(byte);
            var t = stackalloc byte[tLength];
            var tSpan = new Span<byte>(t, tLength);
            info.CopyTo(tSpan.Slice(hashLength));

            byte counter = 1;
            var counterSpan = tSpan.Slice(tSpan.Length - 1);
            counterSpan.Write(counter);
            provider.HmacData(hashType, prk, prkLength, t + hashLength, tLength - hashLength, t, hashLength);
            while (true)
            {
                int amountToCopy = Math.Min(hashLength, output.Length);
                tSpan.Slice(0, amountToCopy).CopyTo(output);
                output = output.Slice(amountToCopy);
                if (output.Length == 0)
                {
                    break;
                }
                counter++;
                counterSpan.Write(counter);
                provider.HmacData(hashType, prk, prkLength, t, tLength, t, hashLength);
            }
        }

        public static unsafe void HkdfExpandLabel(IHashProvider provider, HashType hashType, void* secret, int secretLength,Span<byte> label, Span<byte> hash, Span<byte> output)
        {
            var hkdfSize = HkdfLabelHeaderSize + label.Length + hash.Length;
            var hkdfLabel = stackalloc byte[hkdfSize];
            var hkdfSpan = new Span<byte>(hkdfLabel, hkdfSize);
            hkdfSpan.Write16BitNumber((ushort)output.Length);
            hkdfSpan = hkdfSpan.Slice(sizeof(ushort));
            hkdfSpan.Write((byte)label.Length);
            hkdfSpan = hkdfSpan.Slice(sizeof(byte));
            label.CopyTo(hkdfSpan);
            hkdfSpan = hkdfSpan.Slice(label.Length);
            hkdfSpan.Write((byte)hash.Length);
            hkdfSpan = hkdfSpan.Slice(sizeof(byte));
            hash.CopyTo(hkdfSpan);
            hkdfSpan = new Span<byte>(hkdfLabel, hkdfSize);

            HkdfExpand(provider, hashType, secret, secretLength, hkdfSpan,  output);
        }

        public static unsafe Tuple<byte[],byte[]> ClientServerApplicationTrafficSecret(IHashProvider provider, HashType hashType, void* masterSecret, Span<byte> hash)
        {
            var hashSize = hash.Length;
            var clientSecret = new byte[hashSize];
            var serverSecret = new byte[hashSize];
            HkdfExpandLabel(provider, hashType, masterSecret, hash.Length, Tls1_3Labels.ClientApplicationTrafficSecret, hash, clientSecret);
            HkdfExpandLabel(provider, hashType, masterSecret, hash.Length, Tls1_3Labels.ServerApplicationTrafficSecret, hash, serverSecret);
            return Tuple.Create(clientSecret,serverSecret);
        }

        public static unsafe byte[] ServerHandshakeTrafficSecret(IHashProvider provider, HashType hashType, void* handshakeSecret,Span<byte> hash)
        {
            var output = new byte[hash.Length];
            HkdfExpandLabel(provider, hashType, handshakeSecret, hash.Length, Tls1_3Labels.ServerHandshakeTrafficSecret, hash, output);
            return output;
        }

        public static unsafe byte[] ClientHandshakeTrafficSecret(IHashProvider provider, HashType hashType, void* handshakeSecret, Span<byte> hash)
        {
            var output = new byte[hash.Length];
            HkdfExpandLabel(provider, hashType, handshakeSecret, hash.Length, Tls1_3Labels.ClientHandshakeTrafficSecret, hash, output);
            return output;
        }

        public static unsafe byte[] ResumptionSecret(IHashProvider provider, HashType hashType, void* masterSecret, Span<byte> hash)
        {
            var output = new byte[hash.Length];
            HkdfExpandLabel(provider, hashType, masterSecret, hash.Length, Tls1_3Labels.ResumptionSecret, hash, output);
            return output;
        }

        public unsafe static byte[] FinishedKey(IHashProvider provider, HashType hashType, byte[] handshakeTrafficSecret)
        {
            var output = new byte[provider.HashSize(hashType)];
            fixed(byte* sPtr = handshakeTrafficSecret)
            {
                HkdfExpandLabel(provider, hashType, sPtr, handshakeTrafficSecret.Length, Tls1_3Labels.ServerFinishedKey, new Span<byte>(), output);
            }
            return output;
        }
    }
}
