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

        public unsafe static int SSL_read(SSL ssl, byte[] buffer, int offset, int length)
        {
            fixed(byte* basePtr = buffer)
            {
                var ptr = basePtr + offset;
                var result = SSL_read(ssl, ptr, length);
                return result;
            }
        }
    }
}
