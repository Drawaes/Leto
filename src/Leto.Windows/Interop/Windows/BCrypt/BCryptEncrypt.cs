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
            Span<byte> output, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info)
        {
            fixed (void* inputPtr = &input.DangerousGetPinnableReference())
            fixed (void* outputPtr = &input.DangerousGetPinnableReference())
            {
                var result = BCryptEncrypt(key, inputPtr, input.Length, &info, null, 0, outputPtr, output.Length, out int length, 0);
                ThrowOnErrorReturnCode(result);
                return info;
            }
        }

        internal static unsafe BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO BCryptEncrypt(SafeBCryptKeyHandle key,
            Span<byte> inputOutput, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info)
        {
            fixed (void* ioPtr = &inputOutput.DangerousGetPinnableReference())
            {
                var result = BCryptEncrypt(key, ioPtr, inputOutput.Length, &info, null, 0, ioPtr, inputOutput.Length, out int length, 0);
                ThrowOnErrorReturnCode(result);
                return info;
            }
        }

        internal static unsafe void BCryptEncryptGetTag(SafeBCryptKeyHandle key,
            Span<byte> tag, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO context)
        {
            fixed (void* tagPtr = &tag.DangerousGetPinnableReference())
            {
                context.pbTag = tagPtr;
                context.cbTag = tag.Length;
                context.dwFlags = AuthenticatedCipherModeInfoFlags.None;
                var result = BCryptEncrypt(key, null, 0, &context, null, 0, null, 0, out int size, 0);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
