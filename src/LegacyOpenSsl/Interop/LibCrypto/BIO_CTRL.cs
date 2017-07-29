using System;
using System.Collections.Generic;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class LibCrypto
    {
        public enum BIO_CTRL
        {
            BIO_CTRL_RESET = 1,/* opt - rewind/zero etc */
            BIO_CTRL_EOF = 2,/* opt - are we at the eof */
            BIO_CTRL_INFO = 3,/* opt - extra tit-bits */
            BIO_CTRL_SET = 4,/* man - set the 'IO' type */
            BIO_CTRL_GET = 5,/* man - get the 'IO' type */
            BIO_CTRL_PUSH = 6,/* opt - internal, used to signify change */
            BIO_CTRL_POP = 7,/* opt - internal, used to signify change */
            BIO_CTRL_GET_CLOSE = 8,/* man - set the 'close' on free */
            BIO_CTRL_SET_CLOSE = 9,/* man - set the 'close' on free */
            BIO_CTRL_PENDING = 10,/* opt - is their more data buffered */
            BIO_CTRL_FLUSH = 11,/* opt - 'flush' buffered output */
            BIO_CTRL_DUP = 12,/* man - extra stuff for 'duped' BIO */
            BIO_CTRL_WPENDING = 13,/* opt - number of bytes still to write */
        }
    }
}
