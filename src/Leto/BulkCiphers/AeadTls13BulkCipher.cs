using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.RecordLayer;

namespace Leto.BulkCiphers
{
    public sealed class AeadTls13BulkCipher : AeadBulkCipher
    {
        
        public override void Decrypt(ref ReadableBuffer messageBuffer, RecordType recordType, TlsVersion tlsVersion)
        {
            throw new NotImplementedException();
        }

        public override void Encrypt(ref WritableBuffer writer, ReadableBuffer plainText, RecordType recordType, TlsVersion tlsVersion)
        {
            throw new NotImplementedException();
        }
    }
}
