// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal partial class Interop
{
    /// <summary>
    /// BCrypt types related to symmetric encryption algorithms
    /// </summary>
    internal partial class BCrypt
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_KEY_DATA_BLOB
        {
            internal uint dwMagic;
            internal int dwVersion;
            internal int cbKeyData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
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
        internal enum AuthenticatedCipherModeInfoFlags : uint
        {
            None = 0x00000000,
            ChainCalls = 0x00000001,                           // BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG
            InProgress = 0x00000002,                           // BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG
        }
    }
}
