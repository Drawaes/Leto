using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX ctx, EVP_CIPHER_CTRL type, int arg, void* ptr);

        internal static unsafe int EVP_CIPHER_CTX_SetTag(EVP_CIPHER_CTX ctx, ReadOnlySpan<byte> tag)
        {
            fixed (void* tagPtr = &tag.DangerousGetPinnableReference())
            {
                var result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CIPHER_CTRL.EVP_CTRL_GCM_SET_TAG, tag.Length, tagPtr);
                return ThrowOnErrorReturnCode(result);
            }
        }

        internal static unsafe int EVP_CIPHER_CTX_GetTag(EVP_CIPHER_CTX ctx, Span<byte> tag)
        {
            fixed (void* tagPtr = &tag.DangerousGetPinnableReference())
            {
                var result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CIPHER_CTRL.EVP_CTRL_GCM_GET_TAG, tag.Length, tagPtr);
                return ThrowOnErrorReturnCode(result);
            }
        }
    }
}
