using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal partial class BCrypt
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_KEY_DATA_BLOB
        {
            internal uint dwMagic;
            internal int dwVersion;
            internal int cbKeyData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            internal int cbSize;               // 4
            internal int dwInfoVersion;        // 8
            internal void* pbNonce;            // byte * //16
            internal int cbNonce;              // 20
            internal void* pbAuthData;         // byte * //28
            internal int cbAuthData;           // 32
            internal void* pbTag;              // byte * //40
            internal int cbTag;                // 44
            internal void* pbMacContext;       // byte 52
            internal int cbMacContext;         // 56
            internal int cbAAD;                // 60
            internal long cbData;              // 68
            internal AuthenticatedCipherModeInfoFlags dwFlags; // 72
        }

        [Flags]
        internal enum AuthenticatedCipherModeInfoFlags : uint
        {
            None = 0x00000000,
            ChainCalls = 0x00000001,                           // BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG
            InProgress = 0x00000002,                           // BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_AUTH_TAG_LENGTHS_STRUCT
        {
            internal int dwMinLength;
            internal int dwMaxLength;
            internal int dwIncrement;
        }
    }
}
