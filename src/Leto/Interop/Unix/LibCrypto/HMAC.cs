using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe void* HMAC(EVP_HashType evp_md, void* key, int key_len, void* d, int n, void* md, ref int md_len);

        internal unsafe static int HMAC(EVP_HashType evp, Span<byte> key, Span<byte> data, Span<byte> output)
        {
            fixed(void* keyPtr = &key.DangerousGetPinnableReference())
            fixed(void* dataPtr = &data.DangerousGetPinnableReference())
            fixed(void* outputPtr = &output.DangerousGetPinnableReference())
            {
                int outputLength = output.Length;
                var result = HMAC(evp, keyPtr, key.Length, dataPtr, data.Length, outputPtr, ref outputLength);
                ThrowOnNullPointer(result);
                return outputLength;
            }
        }
    }
}
