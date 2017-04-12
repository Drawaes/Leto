using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;
using Leto.RecordLayer;

namespace Leto.BulkCiphers
{
    public sealed class AeadTls13BulkCipher : AeadBulkCipher
    {
        public override void Decrypt(ref ReadableBuffer messageBuffer, RecordType recordType, TlsVersion tlsVersion)
        {
            var tagBuffer = messageBuffer.Slice(messageBuffer.Length - _key.TagSize);
            messageBuffer = messageBuffer.Slice(0, messageBuffer.Length - _key.TagSize);
            _key.Init(KeyMode.Decryption);
            foreach (var b in messageBuffer)
            {
                if (b.Length == 0) continue;
                _key.Update(b.Span);
            }
            var tagSpan = tagBuffer.ToSpan();
            _key.WriteTag(tagSpan);
            IncrementSequence();
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
            bytesWritten = _key.Update(new Span<byte>(&recordType, sizeof(RecordType)), writer.Buffer.Span);
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
            bytesWritten = _key.Update(new Span<byte>(&recordType, sizeof(RecordType)), writer.Buffer.Span);
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
