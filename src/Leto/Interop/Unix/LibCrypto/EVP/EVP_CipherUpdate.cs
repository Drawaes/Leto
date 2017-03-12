using Leto.BulkCiphers;
using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, void* output, ref int outl, void* input, int inl);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, IntPtr output, ref int outl, ref AdditionalInfo input, int inl);

        internal static unsafe int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, Span<byte> output, Span<byte> input)
        {
            fixed (void* inputPtr = &input.DangerousGetPinnableReference())
            fixed (void* outputPtr = &input.DangerousGetPinnableReference())
            {
                int outputSize = output.Length;
                var result = EVP_CipherUpdate(ctx, outputPtr, ref outputSize, inputPtr, input.Length);
                ThrowOnErrorReturnCode(result);
                return outputSize;
            }
        }

        internal static int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, AdditionalInfo input)
        {
            int size = 0;
            var result = EVP_CipherUpdate(ctx, IntPtr.Zero, ref size, ref input, Marshal.SizeOf<AdditionalInfo>());
            ThrowOnErrorReturnCode(result);
            return size;
        }
    }
}
