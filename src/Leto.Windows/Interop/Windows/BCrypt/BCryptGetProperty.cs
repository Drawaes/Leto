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
        private static extern unsafe NTSTATUS BCryptGetProperty(SafeBCryptHandle hObject, string pszProperty, void* pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        internal static int GetBlockLength(SafeBCryptHandle provider)
        {
            return GetIntProperty(provider, BCryptPropertyStrings.BCRYPT_BLOCK_LENGTH);
        }

        internal unsafe static BCRYPT_AUTH_TAG_LENGTHS_STRUCT GetAuthTagLengths(SafeBCryptHandle provider)
        {
            var size = sizeof(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            var output = default(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            BCryptGetProperty(provider, BCryptPropertyStrings.BCRYPT_AUTH_TAG_LENGTH, &output, size, out int result, 0);
            return output;
        }

        private unsafe static int GetIntProperty(SafeBCryptHandle provider, string property)
        {
            int objectSize;
            var result = BCryptGetProperty(provider, property, &objectSize, 4, out int length, 0);
            ThrowOnErrorReturnCode(result);
            return objectSize;
        }
    }
}
