// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class NCrypt
    {
        [DllImport(Libraries.NCrypt, CharSet = CharSet.Unicode)]
        internal static unsafe extern ErrorCode NCryptExportKey(IntPtr hKey, IntPtr hExportKey, string pszBlobType, IntPtr pParameterList,
            void* pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct _NCryptBufferDesc
        {
            public ulong ulVersion;
            public ulong cBuffers;
            public IntPtr pBuffers;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct _NCryptBuffer
        {
            public ulong cbBuffer;
            public ulong BufferType;
            public IntPtr pvBuffer;
        }
    }
}
