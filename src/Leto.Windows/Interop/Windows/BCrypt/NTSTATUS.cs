using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Windows.Interop
{
    internal partial class BCrypt
    {
        internal enum NTSTATUS : uint
        {
            STATUS_SUCCESS = 0x0,
            STATUS_NOT_FOUND = 0xc0000225,
            STATUS_INVALID_PARAMETER = 0xc000000d,
            STATUS_NO_MEMORY = 0xc0000017,
        }
    }
}
