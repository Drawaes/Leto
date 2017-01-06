using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.RecordLayer;

namespace Leto.Tls13.BulkCipher
{
    public interface IBulkCipherInstance
    {
        int Overhead { get; set; }

        void Decrypt(ref ReadableBuffer messageBuffer);
        void IncrementSequence();
        void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText);
        void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText, RecordType recordType);
    }
}
