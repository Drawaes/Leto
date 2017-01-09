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
        internal struct BCRYPT_AUTH_TAG_LENGTHS_STRUCT
        {
            public int dwMinLength;
            public int dwMaxLength;
            public int dwIncrement;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_ECC_CURVE_NAMES
        {
            public int dwEccCurveNames;
            public IntPtr pEccCurveNames;
        }
    }
}
