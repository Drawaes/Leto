using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.OpenSslFacts.Data
{
    public static class Tls12ClientMessages
    {
        public static readonly byte[] ClientHello = BulkCipherFacts.StringToByteArray(
          @"01 00 00  8d 03 03 00 00 00 00 00
            00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00  00 00 00 00 00 2c cc a8
            cc a9 c0 2f c0 2b c0 30  c0 2c c0 27 c0 13 c0 23
            c0 09 c0 14 c0 0a 00 9c  00 9d 00 3c 00 2f 00 35
            c0 12 00 0a 00 05 c0 11  c0 07 01 00 00 38 00 05
            00 05 01 00 00 00 00 00  0a 00 0a 00 08 00 1d 00
            17 00 18 00 19 00 0b 00  02 01 00 00 0d 00 0e 00
            0c 04 01 04 03 05 01 05  03 02 01 02 03 ff 01 00
            01 00 00 12 00 00");
        public static readonly byte[] ClientKeyExchange = BulkCipherFacts.StringToByteArray(
          @"10 00 00 82 00 80 b9 65  8d bf a7
            c8 4b 79 ce 6f cb 8b 13  1c ac b9 7d 66 5e e9 ba
            1d 71 4e a9 e9 34 ae f6  64 65 90 3b d8 16 52 a2
            6f f4 cb 8a 13 74 a2 ee  b7 27 69 b4 41 c0 90 68
            bc 02 69 e1 c6 48 4f 39  36 30 25 ca 4c 17 ce 83
            9e 08 56 e3 05 49 93 9e  2e c4 fb e6 c8 01 f1 0f
            c5 70 0f 08 83 48 e9 48  ef 6e 50 8b 05 7e e5 84
            25 fa 55 c7 ae 31 02 27  00 ef 3f 98 86 20 12 89
            91 59 28 b4 f7 d7 af d2  69 61 35");
    }
}
