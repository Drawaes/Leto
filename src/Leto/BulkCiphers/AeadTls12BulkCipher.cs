using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.Internal;
using Leto.RecordLayer;

namespace Leto.BulkCiphers
{
    public sealed class AeadTls12BulkCipher : AeadBulkCipher
    {
        public override void Decrypt(ref ReadableBuffer messageBuffer, RecordType recordType, TlsVersion tlsVersion)
        {
            var addInfo = new AdditionalInfo()
            {
                RecordType = recordType,
                TlsVersion = tlsVersion,
                SequenceNumber = _sequenceNumber,
                PlainTextLength = (ushort)(messageBuffer.Length - sizeof(ulong) - _key.TagSize),
            };
           messageBuffer.Slice(0, sizeof(ulong)).CopyTo(_key.IV.Slice(4).Span);
            var tagSpan = messageBuffer.Slice(messageBuffer.Length - _key.TagSize).ToSpan();
            messageBuffer = messageBuffer.Slice(sizeof(ulong), addInfo.PlainTextLength);
            _key.Init(KeyMode.Decryption);
            _key.AddAdditionalInfo(ref addInfo);
            _key.SetTag(tagSpan);
            Decrypt(ref messageBuffer);
        }

        public override void Encrypt(ref WritableBuffer writer, ReadableBuffer plainText, RecordType recordType, TlsVersion tlsVersion)
        {
            _key.IV.Span.Slice(4).WriteBigEndian(_sequenceNumber);
            _key.Init(KeyMode.Encryption);
            var additionalInfo = new AdditionalInfo()
            {
                SequenceNumber = _sequenceNumber,
                RecordType = recordType,
                TlsVersion = tlsVersion,
                PlainTextLength = (ushort)plainText.Length
            };
            _key.AddAdditionalInfo(ref additionalInfo);
            writer.WriteBigEndian(_sequenceNumber);
            var totalBytes = plainText.Length;
            foreach (var b in plainText)
            {
                if (b.Length == 0) continue;
                totalBytes -= b.Length;
                writer.Ensure(b.Length);
                int bytesWritten;
                if (totalBytes == 0)
                {
                    bytesWritten = _key.Finish(b.Span, writer.Buffer.Span);
                    writer.Advance(bytesWritten);
                    break;
                }
                bytesWritten = _key.Update(b.Span, writer.Buffer.Span);
                writer.Advance(bytesWritten);
            }
            IncrementSequence();
            WriteTag(ref writer);
        }

        public override void Encrypt(ref WritableBuffer writer, Span<byte> plainText, RecordType recordType, TlsVersion tlsVersion)
        {
            _key.IV.Span.Slice(4).WriteBigEndian(_sequenceNumber);
            _key.Init(KeyMode.Encryption);
            var additionalInfo = new AdditionalInfo()
            {
                SequenceNumber = _sequenceNumber,
                RecordType = recordType,
                TlsVersion = tlsVersion,
                PlainTextLength = (ushort)plainText.Length
            };
            _key.AddAdditionalInfo(ref additionalInfo);
            writer.WriteBigEndian(_sequenceNumber);
            writer.Ensure(plainText.Length);
            var bytesWritten = _key.Finish(plainText, writer.Buffer.Span);
            writer.Advance(bytesWritten);
            IncrementSequence();
            WriteTag(ref writer);
        }
    }
}