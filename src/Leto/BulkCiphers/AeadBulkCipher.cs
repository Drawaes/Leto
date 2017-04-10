using Leto.RecordLayer;
using System;
using System.IO.Pipelines;

namespace Leto.BulkCiphers
{
    public abstract class AeadBulkCipher : IDisposable
    {
        protected const int AdditionalInfoHeaderSize = 13;
        protected ulong _sequenceNumber;
        protected IBulkCipherKey _key;

        public AeadBulkCipher()
        {
        }

        public int Overhead => _key.TagSize;
        public int IVSize => _key.IV.Length;
                
        public abstract void Decrypt(ref ReadableBuffer messageBuffer, RecordType recordType, TlsVersion tlsVersion);
        public abstract void Encrypt(ref WritableBuffer writer, ReadableBuffer plainText, RecordType recordType, TlsVersion tlsVersion);
        public void SetKey(IBulkCipherKey key) => _key = key;
        public virtual void IncrementSequence() => _sequenceNumber++;
                
        protected void WriteTag(ref WritableBuffer writer)
        {
            writer.Ensure(_key.TagSize);
            _key.ReadTag(writer.Buffer.Span.Slice(0, _key.TagSize));
            writer.Advance(_key.TagSize);
        }

        public void Dispose()
        {
            _key?.Dispose();
            _key = null;
            GC.SuppressFinalize(this);
        }

        ~AeadBulkCipher() => Dispose();
    }
}
