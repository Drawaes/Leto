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
        private static extern unsafe NTSTATUS BCryptHashData(SafeBCryptHashHandle hHash, void* pbInput, int cbInput, int dwFlags);

        internal static unsafe void BCryptHashData(SafeBCryptHashHandle handle, ReadOnlySpan<byte> span)
        {
            fixed(void* ptr = &span.DangerousGetPinnableReference())
            {
                var result = BCryptHashData(handle, ptr, span.Length, 0);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
