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
            var tagBuffer = messageBuffer.Slice(messageBuffer.Length - _key.TagSize);
            messageBuffer = messageBuffer.Slice(sizeof(ulong), addInfo.PlainTextLength);
            _key.Init(KeyMode.Decryption);
            _key.AddAdditionalInfo(ref addInfo);
            foreach (var b in messageBuffer)
            {
                if (b.Length == 0) continue;
                _key.Update(b.Span);
            }
            var tagSpan = tagBuffer.ToSpan();
            _key.WriteTag(tagSpan);
            _sequenceNumber++;
        }

        public override void Encrypt(ref WritableBuffer writer, ReadableBuffer plainText, RecordType recordType, TlsVersion tlsVersion)
        {
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
            foreach (var b in plainText)
            {
                if (b.Length == 0) continue;
                writer.Ensure(b.Length);
                var bytesWritten = _key.Update(b.Span, writer.Buffer.Span);
                writer.Advance(bytesWritten);
            }
            WriteTag(ref writer);
            IncrementSequence();
        }

        private AdditionalInfo ReadAdditionalInfo(ref ReadableBuffer reader)
        {
            var headerSpan = new BigEndianAdvancingSpan(reader.Slice(0, AdditionalInfoHeaderSize).ToSpan());
            var additionalInfo = new AdditionalInfo() { SequenceNumber = _sequenceNumber };
            additionalInfo.RecordType = headerSpan.Read<RecordType>();
            additionalInfo.TlsVersion = headerSpan.Read<TlsVersion>();
            additionalInfo.PlainTextLength = headerSpan.Read<ushort>();
            additionalInfo.PlainTextLength -= (ushort)(_key.TagSize + sizeof(ulong));
            headerSpan.ToSpan().CopyTo(_key.IV.Span.Slice(4));
            return additionalInfo;
        }
    }
}