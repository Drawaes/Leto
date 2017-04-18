using System;
using System.Binary;
using System.IO.Pipelines;
using Leto.RecordLayer;

namespace Leto.BulkCiphers
{
    public sealed class AeadTls13BulkCipher : AeadBulkCipher
    {
        public override void Decrypt(ref ReadableBuffer messageBuffer, RecordType recordType, TlsVersion tlsVersion)
        {
            var tagSpan = messageBuffer.Slice(messageBuffer.Length - _key.TagSize).ToSpan();
            messageBuffer = messageBuffer.Slice(0, messageBuffer.Length - _key.TagSize);
            _key.Init(KeyMode.Decryption);
            _key.SetTag(tagSpan);
            Decrypt(ref messageBuffer);
        }

        public unsafe override void Encrypt(ref WritableBuffer writer, ReadableBuffer plainText, RecordType recordType, TlsVersion tlsVersion)
        {
            _key.Init(KeyMode.Encryption);
            int bytesWritten;
            foreach (var b in plainText)
            {
                if (b.Length == 0) continue;
                writer.Ensure(b.Length);
                bytesWritten = _key.Update(b.Span, writer.Buffer.Span);
                writer.Advance(bytesWritten);
            }
            writer.Ensure(sizeof(RecordType));
            bytesWritten = _key.Finish(new Span<byte>(&recordType, sizeof(RecordType)), writer.Buffer.Span);
            writer.Advance(bytesWritten);
            WriteTag(ref writer);
            IncrementSequence();
        }

        public unsafe override void Encrypt(ref WritableBuffer writer, Span<byte> plainText, RecordType recordType, TlsVersion tlsVersion)
        {
            _key.Init(KeyMode.Encryption);
            int bytesWritten;
            writer.Ensure(plainText.Length);
            bytesWritten = _key.Update(plainText, writer.Buffer.Span);
            writer.Advance(bytesWritten);
            writer.Ensure(sizeof(RecordType));
            bytesWritten = _key.Finish(new Span<byte>(&recordType, sizeof(RecordType)), writer.Buffer.Span);
            writer.Advance(bytesWritten);
            WriteTag(ref writer);
            IncrementSequence();
        }

        public override unsafe void IncrementSequence()
        {
            var ivSpan = _key.IV.Span;
            var ivLong = ivSpan.Slice(4).Read<ulong>();
            var result = ivLong ^ BufferExtensions.Reverse(_sequenceNumber);
            base.IncrementSequence();
            result = result ^ BufferExtensions.Reverse(_sequenceNumber);
            ivSpan.Slice(4).Write(result);
        }
    }
}
