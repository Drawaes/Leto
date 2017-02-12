using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.RecordLayer;

namespace Leto.Tls13.BulkCipher
{
    public interface IBulkCipherInstance:IDisposable
    {
        int Overhead { get; }
        int KeyLength { get; }
        int IVLength { get; }
        void SetKey(Span<byte> key);
        void SetIV(Span<byte> iv);
        void WriteNonce(ref WritableBuffer buffer);
        void Decrypt(ref ReadableBuffer messageBuffer);
        void Encrypt(ref WritableBuffer buffer, RecordType recordType);
        void WithPadding(int paddingSize);
        void DecryptWithAuthData(ref ReadableBuffer messageBuffer);
        void EncryptWithAuthData(ref WritableBuffer buffer, RecordType recordType, ushort tlsVersion, int plaintextLength);
    }
}
