using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class OpenSsl
    {
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int SSL_write(SSL ssl, void* buf, int num);

        public unsafe static int SSL_write(SSL ssl, Span<byte> output)
        {
            fixed (byte* ptr = &output.DangerousGetPinnableReference())
            {
                var result = SSL_write(ssl, ptr, output.Length);
                return result;
            }
        }
    }
}
