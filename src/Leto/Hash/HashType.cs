﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Hash
{
    //Numbers from https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
    public enum HashType : byte
    {
        SHA256 = 4,
        SHA384 = 5,
        SHA512 = 6,
    }
}
