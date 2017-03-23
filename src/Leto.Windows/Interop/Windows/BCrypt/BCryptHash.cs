﻿using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal partial class BCrypt
    {
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
        private static unsafe extern NTSTATUS BCryptHash(SafeBCryptAlgorithmHandle hAlgorithm, void* pbSecret, uint cbSecret, void* pbInput, uint cbInput, void* pbOutput, uint cbOutput);

        internal static unsafe void BCryptHash(SafeBCryptAlgorithmHandle handle, ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> output)
        {
            fixed(void* keyPtr = &key.DangerousGetPinnableReference())
            fixed(void* dataPtr = &data.DangerousGetPinnableReference())
            fixed(void* outputPtr = &output.DangerousGetPinnableReference())
            {
                var result = BCryptHash(handle, keyPtr, (uint)key.Length, dataPtr, (uint)data.Length, outputPtr, (uint)output.Length);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
