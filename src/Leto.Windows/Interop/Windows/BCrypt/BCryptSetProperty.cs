using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal static partial class BCrypt
    {
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
        private static extern unsafe NTSTATUS BCryptSetProperty(SafeBCryptHandle hObject, string pszProperty, void* pbInput, int cbInput, int dwFlags);
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
        private static extern unsafe NTSTATUS BCryptSetProperty(SafeBCryptHandle hObject, string pszProperty, string pbInput, int cbInput, int dwFlags);

        internal static void BCryptSetEccCurve(SafeBCryptHandle handle, string curveName)
        {
            var result = BCryptSetProperty(handle, BCryptPropertyStrings.BCRYPT_ECC_CURVE_NAME, curveName, (curveName.Length + 1) * sizeof(char), 0);
            ThrowOnErrorReturnCode(result);
        }
    }
}
