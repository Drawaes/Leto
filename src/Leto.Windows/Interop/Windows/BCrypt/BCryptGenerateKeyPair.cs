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
        private static unsafe extern NTSTATUS BCryptGenerateKeyPair(SafeBCryptAlgorithmHandle hAlgorithm, out SafeBCryptKeyHandle phKey, int dwLength, int dwFlags);

        internal static SafeBCryptKeyHandle BCryptGenerateAndFinalizeKeyPair(SafeBCryptAlgorithmHandle handle)
        {
            var result = BCryptGenerateKeyPair(handle, out SafeBCryptKeyHandle key, 0, 0);
            ThrowOnErrorReturnCode(result);
            result = BCryptFinalizeKeyPair(key, 0);
            ThrowOnErrorReturnCode(result);
            return key;
        }
    }
}
