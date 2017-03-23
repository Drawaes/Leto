using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal static partial class BCrypt
    {
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode, EntryPoint =nameof(BCryptOpenAlgorithmProvider))]
        private static extern NTSTATUS Internal_BCryptOpenAlgorithmProvider(out SafeBCryptAlgorithmHandle phAlgorithm, string pszAlgId, string pszImplementation, BCryptOpenAlgorithmProviderFlags dwFlags);

        internal static SafeBCryptAlgorithmHandle BCryptOpenAlgorithmProvider(string algoId)
        {
            var result = Internal_BCryptOpenAlgorithmProvider(out SafeBCryptAlgorithmHandle outHandle, algoId, null, BCryptOpenAlgorithmProviderFlags.None);
            ThrowOnErrorReturnCode(result);
            return outHandle;
        }

        internal static SafeBCryptAlgorithmHandle BCryptOpenECCurveAlgorithmProvider(string curveName)
        {
            var handle = BCryptOpenAlgorithmProvider("ECDH");
            BCryptSetEccCurve(handle, curveName);
            return handle;
        }

        [Flags]
        private enum BCryptOpenAlgorithmProviderFlags : int
        {
            None = 0x00000000,
            BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008,
        }
    }
}
