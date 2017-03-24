using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Windows.Interop
{
    internal static partial class BCrypt
    {
        private const int BCRYPT_KEY_DATA_BLOB_MAGIC = 0x4d42444b; // 'KDBM'
        private const int BCRYPT_KEY_DATA_BLOB_VERSION1 = 1;
    }
}
