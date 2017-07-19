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

        public unsafe static int SSL_write(SSL ssl, byte[] array, int offset, int length)
        {
            fixed (void* ptr = &array[offset])
            {
                var result = SSL_write(ssl, ptr, length);
                return result;
            }
        }
    }
}
