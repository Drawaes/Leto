﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.BulkCipher
{
    public enum BulkCipherType
    {
        AES_128_GCM,
        AES_256_GCM,
        CHACHA20_POLY1305,
        AES_128_CCM,
        AES_128_CCM_8,
    }
}
