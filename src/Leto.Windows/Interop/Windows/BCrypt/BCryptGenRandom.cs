using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal static partial class BCrypt
    {
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
        private unsafe static extern NTSTATUS BCryptGenRandom(void* algoHandle, void* pbBuffer, int cbBuffer, uint dwFlags);
        private const uint BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002;

        internal unsafe static void BCryptGenRandom(Span<byte> bufferToFill)
        {
            fixed(void* ptr = &bufferToFill.DangerousGetPinnableReference())
            {
                var result = BCryptGenRandom(null, ptr, bufferToFill.Length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
