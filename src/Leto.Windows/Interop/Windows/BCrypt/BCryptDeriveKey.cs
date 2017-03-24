using Leto.Hashes;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal partial class BCrypt
    {
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
        private static unsafe extern NTSTATUS BCryptDeriveKey(SafeBCryptSecretHandle hSharedSecret, string pwszKDF, void* pParameterList, void* pbDerivedKey, int cbDerivedKey, out int pcbResult, int dwFlags);

        internal static unsafe void BCryptDeriveHmacKey(SafeBCryptSecretHandle handle, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            var buffDescription = new BCryptBufferDesc();
            var bufferArray = stackalloc BCryptBuffer[2];
            var algId = Encoding.Unicode.GetBytes(hashType.ToString() + "\0");
            buffDescription.pBuffers = (IntPtr)bufferArray;
            buffDescription.cBuffers = 2;
            fixed (byte* algPtr = algId)
            fixed (void* outputPtr = &output.DangerousGetPinnableReference())
            fixed (void* seedPtr = &seed.DangerousGetPinnableReference())
            {
                bufferArray[0] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_HASH_ALGORITHM, cbBuffer = algId.Length, pvBuffer = algPtr };
                bufferArray[1] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_HMAC_KEY, cbBuffer = seed.Length, pvBuffer = seedPtr };
                var result = BCryptDeriveKey(handle, BCRYPT_KDF_HMAC, &buffDescription, outputPtr, output.Length, out int sizeOfResult, 0);
                ThrowOnErrorReturnCode(result);
            }
        }

        internal static unsafe void BCryptDeriveKey(SafeBCryptSecretHandle handle, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            uint version = 0x0303;
            var buffDescription = new BCryptBufferDesc();
            var bufferArray = stackalloc BCryptBuffer[4];
            var algId = Encoding.Unicode.GetBytes(hashType.ToString() + "\0");
            fixed (void* algPtr = algId)
            fixed (void* labelPtr = TlsConstants.Tls12.Label_MasterSecret)
            fixed (void* outputPtr = &output.DangerousGetPinnableReference())
            fixed (void* seedPtr = &seed.DangerousGetPinnableReference())
            {
                bufferArray[0] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_HASH_ALGORITHM, cbBuffer = algId.Length, pvBuffer = algPtr };
                bufferArray[1] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_TLS_PRF_LABEL, cbBuffer = TlsConstants.Tls12.Label_MasterSecret.Length, pvBuffer = labelPtr };
                bufferArray[2] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_TLS_PRF_SEED, cbBuffer = seed.Length, pvBuffer = seedPtr };
                bufferArray[3] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_TLS_PRF_PROTOCOL, cbBuffer = 4, pvBuffer = &version };
                buffDescription.cBuffers = 4;
                buffDescription.pBuffers = (IntPtr)bufferArray;
                var result = BCryptDeriveKey(handle, BCRYPT_KDF_TLS_PRF, &buffDescription, outputPtr, output.Length, out int sizeOfResult, 0);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
