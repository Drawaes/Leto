using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private extern static BIO BIO_new_file(string filename, string mode);

        public static BIO BIO_new_file_read(string fileName) => BIO_new_file(fileName, "r");
        public static BIO BIO_new_file_write(string filename) => BIO_new_file(filename, "w");
    }
}
