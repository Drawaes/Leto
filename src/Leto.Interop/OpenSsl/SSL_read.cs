using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class OpenSsl
    {
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int SSL_read(SSL ssl, void* buf, int num);

        public unsafe static int SSL_read(SSL ssl, Span<byte> input)
        {
            fixed(void* ptr = &input.DangerousGetPinnableReference())
            {
                var result = SSL_read(ssl, ptr, input.Length);
                return result;
            }
        }
    }
}
