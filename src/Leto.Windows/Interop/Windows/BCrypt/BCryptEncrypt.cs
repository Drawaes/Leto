using Leto.BulkCiphers;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal partial class BCrypt
    {
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
        private static unsafe extern NTSTATUS BCryptEncrypt(SafeBCryptKeyHandle hKey, void* pbInput, int cbInput, void* pPaddingInfo, void* pbIV, int cbIV, void* pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        internal static unsafe BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO BCryptEncrypt(SafeBCryptKeyHandle key, Span<byte> input,
            Span<byte> output, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info, void* ivBuffer)
        {
            fixed (void* inputPtr = &input.DangerousGetPinnableReference())
            fixed (void* outputPtr = &input.DangerousGetPinnableReference())
            {
                var result = BCryptEncrypt(key, inputPtr, input.Length, &info, ivBuffer, info.cbNonce,  outputPtr, output.Length, out int length, 0);
                ThrowOnErrorReturnCode(result);
                return info;
            }
        }

        internal static unsafe BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO BCryptEncrypt(SafeBCryptKeyHandle key,
            Span<byte> inputOutput, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info, void* ivBuffer)
        {
            fixed (void* ioPtr = &inputOutput.DangerousGetPinnableReference())
            {
                var result = BCryptEncrypt(key, ioPtr, inputOutput.Length, &info, ivBuffer, info.cbNonce, ioPtr, inputOutput.Length, out int length, 0);
                ThrowOnErrorReturnCode(result);
                return info;
            }
        }

        internal static unsafe void BCryptEncryptGetTag(SafeBCryptKeyHandle key, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO context, void* ivBuffer)
        {
            context.dwFlags &= ~AuthenticatedCipherModeInfoFlags.ChainCalls;
            var result = BCryptEncrypt(key, null, 0, &context, ivBuffer, context.cbNonce, null, 0, out int size, 0);
            ThrowOnErrorReturnCode(result);
        }

        internal static unsafe void BCryptEncrypt(SafeBCryptKeyHandle key, Span<byte> iv, Span<byte> tag, Span<byte> input, Span<byte> output)
        {
            fixed (void* ivPtr = &iv.DangerousGetPinnableReference())
            fixed (void* tagPtr = &tag.DangerousGetPinnableReference())
            fixed (void* inputPtr = &input.DangerousGetPinnableReference())
            fixed (void* outputPtr = &output.DangerousGetPinnableReference())
            {
                var encryptInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
                {
                    cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>(),
                    cbAuthData = 0,
                    cbMacContext = 0,
                    cbNonce = 12,
                    pbMacContext = null,
                    pbAuthData = null,
                    dwFlags = AuthenticatedCipherModeInfoFlags.None,
                    dwInfoVersion = 1,
                    pbNonce = ivPtr,
                    cbTag = tag.Length,
                    pbTag = tagPtr
                };
                var result = BCryptEncrypt(key, inputPtr, input.Length, &encryptInfo, null, 0, outputPtr, output.Length, out int bytesWritten, 0);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
