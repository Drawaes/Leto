// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

internal partial class Interop
{
    internal partial class BCrypt
    {
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
        internal static unsafe extern NTSTATUS BCryptEnumAlgorithms(EnumAlgorithmsFlags dwAlgOperations, out uint pAlgCount, out IntPtr algoArray, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszName;
            public uint dwClass;
            public uint dwFlags;

            public override string ToString()
            {
                return pszName;
            }
        }

        [Flags]
        internal enum EnumAlgorithmsFlags : uint
        {
            BCRYPT_CIPHER_OPERATION = 0x00000001, // Include the cipher algorithms in the enumeration.
            BCRYPT_HASH_OPERATION = 0x00000002, // Include the hash algorithms in the enumeration.
            BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x00000004, //Include the asymmetric encryption algorithms in the enumeration.
            BCRYPT_SECRET_AGREEMENT_OPERATION = 0x00000008, // Include the secret agreement algorithms in the enumeration.
            BCRYPT_SIGNATURE_OPERATION = 0x00000010, // Include the signature algorithms in the enumeration.
            BCRYPT_RNG_OPERATION = 0x00000020, // Include the random number generator (RNG) algorithms in the enumeration.
        }
    }
}

