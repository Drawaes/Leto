using Leto.BulkCiphers;
using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_CipherInit_ex(EVP_CIPHER_CTX ctx, EVP_BulkCipher_Type type, void* impl, void* key, void* iv, int enc);

        internal static unsafe void EVP_CipherInit_ex(EVP_CIPHER_CTX ctx, EVP_BulkCipher_Type type, Span<byte> key, Span<byte> iv, KeyMode mode)
        {
            fixed (void* keyPtr = &key.DangerousGetPinnableReference())
            fixed (void* ivPtr = &iv.DangerousGetPinnableReference())
            {
                var result = EVP_CipherInit_ex(ctx, type, null, keyPtr, ivPtr, (int)mode);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
