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
        private unsafe struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            internal int cbSize;
            internal int dwInfoVersion;
            internal IntPtr pbNonce;            // byte * //16
            internal int cbNonce;
            internal IntPtr pbAuthData;         // byte * //28
            internal int cbAuthData;
            internal IntPtr pbTag;              // byte * //40
            internal int cbTag;
            internal IntPtr pbMacContext;       // byte *
            internal int cbMacContext;
            internal int cbAAD;
            internal long cbData;
            internal AuthenticatedCipherModeInfoFlags dwFlags;
        }

        [Flags]
        private enum AuthenticatedCipherModeInfoFlags : uint
        {
            None = 0x00000000,
            ChainCalls = 0x00000001,                           // BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG
            InProgress = 0x00000002,                           // BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG
        }
    }
}
