using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [System.Diagnostics.DebuggerHidden()]
        private unsafe static int ThrowOnErrorReturnCode(int returnCode)
        {
            if (returnCode != 1) ThrowSecurityException();
            return returnCode;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        [System.Diagnostics.DebuggerHidden()]
        private static unsafe void ThrowSecurityException()
        {
            //512 is defined in openssl as the maximum buffer size needed
            var tempBuffer = new byte[512];
            fixed (byte* buffPointer = tempBuffer)
            {
                var errCode = ERR_get_error();
                ERR_error_string_n(errCode, buffPointer, (UIntPtr)tempBuffer.Length);
                var errorString = Marshal.PtrToStringAnsi((IntPtr)buffPointer);
                throw new System.Security.SecurityException($"{errCode}-{errorString}");
            }
        }

        [System.Diagnostics.DebuggerHidden()]
        private static unsafe void* ThrowOnNullPointer(void* ptr)
        {
            if (ptr == null) ThrowSecurityException();
            return ptr;
        }

        [System.Diagnostics.DebuggerHidden()]
        private static IntPtr ThrowOnError(IntPtr returnCode)
        {
            if (returnCode.ToInt64() < 1) ThrowSecurityException();
            return returnCode;
        }
    }
}
