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
        private static unsafe extern NTSTATUS BCryptImportKeyPair(SafeBCryptAlgorithmHandle hAlgorithm, IntPtr hImportKey, string pszBlobType, out SafeBCryptKeyHandle phKey, void* pbInput, int cbInput, int dwFlags);

        internal static unsafe SafeBCryptKeyHandle BCryptImportECKey(SafeBCryptAlgorithmHandle algoHandle, Span<byte> keySpan)
        {
            int cbKey;
            cbKey = keySpan.Length / 2;
            int keyLength = keySpan.Length;
            //Now we have the point and can load the key
            var keyBuffer = new byte[keyLength + 8];
            var blobHeader = new BCRYPT_ECCKEY_BLOB()
            {
                Magic = KeyBlobMagicNumber.BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC,
                cbKey = cbKey
            };
            ((Span<byte>)keyBuffer).Write(blobHeader);
            keySpan.CopyTo(keyBuffer.Slice(Marshal.SizeOf<BCRYPT_ECCKEY_BLOB>()));
            fixed (void* ptr = keyBuffer)
            {
                var result = BCryptImportKeyPair(algoHandle, IntPtr.Zero, KeyBlobType.BCRYPT_ECCPUBLIC_BLOB, out SafeBCryptKeyHandle keyHandle, ptr, keyBuffer.Length, 0);
                ThrowOnErrorReturnCode(result);
                return keyHandle;
            }
        }
    }
}
