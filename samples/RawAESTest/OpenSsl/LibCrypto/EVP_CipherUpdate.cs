using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, void* output, ref int outl, void* input, int inl);
        
        internal static unsafe int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, Span<byte> output, Span<byte> input)
        {
            fixed (void* inputPtr = &input.DangerousGetPinnableReference())
            fixed (void* outputPtr = &output.DangerousGetPinnableReference())
            {
                var outputSize = output.Length;
                var result = EVP_CipherUpdate(ctx, outputPtr, ref outputSize, inputPtr, input.Length);
                ThrowOnErrorReturnCode(result);
                return outputSize;
            }
        }

        internal static unsafe int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, Span<byte> inputOutput)
        {
            fixed (void* ptr = &inputOutput.DangerousGetPinnableReference())
            {
                var outputSize = inputOutput.Length;
                var result = EVP_CipherUpdate(ctx, ptr, ref outputSize, ptr, outputSize);
                ThrowOnErrorReturnCode(result);
                return outputSize;
            }
        }
    }
}
