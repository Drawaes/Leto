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
        private static extern NTSTATUS BCryptImportKey(SafeBCryptAlgorithmHandle hAlgorithm, IntPtr hImportKey, string pszBlobType, out SafeBCryptKeyHandle phKey, IntPtr pbKeyObject, int cbKeyObject, IntPtr pbInput, int cbInput, int dwFlags);

        internal static unsafe SafeBCryptKeyHandle BCryptImportKey(SafeBCryptAlgorithmHandle algoHandle, Span<byte> key)
        {
            var keyBlob = stackalloc byte[sizeof(BCRYPT_KEY_DATA_BLOB) + key.Length];
            var pkeyDataBlob = (BCRYPT_KEY_DATA_BLOB*)keyBlob;
            pkeyDataBlob->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
            pkeyDataBlob->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
            pkeyDataBlob->cbKeyData = key.Length;
            var keyBlobSpan = new Span<byte>(keyBlob + sizeof(BCRYPT_KEY_DATA_BLOB), key.Length);
            key.CopyTo(keyBlobSpan);
            var result = BCryptImportKey(algoHandle, IntPtr.Zero, "KeyDataBlob", out SafeBCryptKeyHandle keyHandle, IntPtr.Zero, 0, (IntPtr)keyBlob, sizeof(BCRYPT_KEY_DATA_BLOB) + key.Length, 0);
            ThrowOnErrorReturnCode(result);
            return keyHandle;
        }
    }
}
