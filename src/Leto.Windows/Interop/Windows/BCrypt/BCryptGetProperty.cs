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

        internal static int GetObjectLength(SafeBCryptHandle provider)
        {
            return GetIntProperty(provider, BCryptPropertyStrings.BCRYPT_OBJECT_LENGTH);
        }

        internal unsafe static BCRYPT_AUTH_TAG_LENGTHS_STRUCT GetAuthTagLengths(SafeBCryptHandle provider)
        {
            var size = sizeof(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            var output = default(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            BCryptGetProperty(provider, BCryptPropertyStrings.BCRYPT_AUTH_TAG_LENGTH, &output, size, out int result, 0);
            return output;
        }

        internal static string GetBlockChainingMode(SafeBCryptHandle provider)
        {
            return GetStringProperty(provider, BCryptPropertyStrings.BCRYPT_CHAINING_MODE);
        }

        private unsafe static string GetStringProperty(SafeBCryptHandle provider, string property)
        {
            var result = BCryptGetProperty(provider, property, null, 0, out int objectSize, 0);
            ThrowOnErrorReturnCode(result);
            var buffer = stackalloc byte[objectSize];
            result = BCryptGetProperty(provider, property, buffer, objectSize, out objectSize, 0);
            return Marshal.PtrToStringUni((IntPtr)buffer);
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
