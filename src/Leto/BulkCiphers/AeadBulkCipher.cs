using Leto.RecordLayer;
using System;
using System.IO.Pipelines;

namespace Leto.BulkCiphers
{
    public sealed class AeadBulkCipher : IDisposable
    {
        private const int AdditionalInfoHeaderSize = 13;
        private readonly byte[] _sequence;
        private ulong _sequenceNumber;
        private IBulkCipherKey _key;
        private byte _paddingSize;

        public AeadBulkCipher(IBulkCipherKey key)
        {
            _sequence = new byte[key.IV.Length];
            _key = key;
        }

        public byte PaddingSize { get => _paddingSize; set => _paddingSize = value; }
        public int Overhead => _key.TagSize + _paddingSize;
        public int KeySize => _key.Key.Length;
        public int IVSize => _key.IV.Length;

        public void SetKey(Span<byte> key) => key.CopyTo(_key.Key.Span);
        public void SetIV(Span<byte> iv) => iv.CopyTo(_key.IV.Span);
        public void WriteNonce(ref WritableBuffer buffer) => buffer.Write(_key.IV.Span.Slice(4));

        public void Decrypt(ref ReadableBuffer messageBuffer, bool requiresAdditionalInfo)
        {
            int plainTextSize, plainTextStart;
            if (requiresAdditionalInfo)
            {
                var addInfo = ReadAdditionalInfo(ref messageBuffer);
                _key.Init(KeyMode.Decryption);
                _key.AddAdditionalInfo(addInfo);
                plainTextSize = addInfo.PlainTextLength;
                plainTextStart = AdditionalInfoHeaderSize;
            }
            else
            {
                _key.Init(KeyMode.Decryption);
                plainTextSize = messageBuffer.Length - _key.TagSize;
                plainTextStart = 0;
            }
            ReadTag(ref messageBuffer);
            messageBuffer = messageBuffer.Slice(plainTextStart, plainTextSize);
            foreach (var b in messageBuffer)
            {
                if (b.Length == 0) continue;
                _key.Update(b.Span);
            }
            _key.Finish();
            IncrementSequence();
        }

        public void EncryptWithAuthData(ref WritableBuffer buffer, RecordType recordType, ushort tlsVersion, int plaintextLength)
        {
            var plainText = buffer.AsReadableBuffer();
            plainText = plainText.Slice(plainText.Length - plaintextLength);
            _key.Init(KeyMode.Encryption);
            WriteAdditionalInfo(recordType, tlsVersion, plaintextLength);

            foreach (var b in plainText)
            {
                if (b.Length == 0) continue;
                _key.Update(b.Span);
            }
            _key.Finish();
            WriteTag(ref buffer);
            _sequenceNumber++;
            IncrementSequence();
        }

        public void IncrementSequence()
        {
            var vPtr = _key.IV.Span;
            var i = vPtr.Length - 1;
            while (i > 3)
            {
                unchecked
                {
                    var val = vPtr[i] ^ _sequence[i];
                    _sequence[i] = (byte)(_sequence[i] + 1);
                    vPtr[i] = (byte)(_sequence[i] ^ val);
                    if (_sequence[i] > 0) return;
                }
                i -= 1;
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Failed to increment sequence on Aead Cipher");
        }

        private void WriteAdditionalInfo(RecordType recordType, ushort tlsVersion, int plaintextLength)
        {
            var additionalInfo = new AdditionalInfo()
            {
                SequenceNumber = _sequenceNumber,
                RecordType = recordType,
                TlsVersion = tlsVersion,
                PlainTextLength = (ushort)plaintextLength
            };
            _key.AddAdditionalInfo(additionalInfo);
        }

        private AdditionalInfo ReadAdditionalInfo(ref ReadableBuffer messageBuffer)
        {
            var headerSpan = messageBuffer.Slice(0, AdditionalInfoHeaderSize).ToSpan();

            var additionalInfo = new AdditionalInfo() { SequenceNumber = _sequenceNumber };
            (additionalInfo.RecordType, headerSpan) = headerSpan.Consume<RecordType>();
            (additionalInfo.TlsVersion, headerSpan) = headerSpan.Consume<ushort>();
            (additionalInfo.PlainTextLengthBigEndian, headerSpan) = headerSpan.Consume<ushort>();
            additionalInfo.PlainTextLength -= (ushort)(_key.TagSize + sizeof(ulong));

            headerSpan.CopyTo(_key.IV.Span.Slice(4));
            return additionalInfo;
        }

        private void ReadTag(ref ReadableBuffer messageBuffer)
        {
            var tagBuffer = messageBuffer.Slice(messageBuffer.Length - _key.TagSize);
            var tagSpan = tagBuffer.ToSpan();
            _key.WriteTag(tagSpan);
        }

        private void WriteTag(ref WritableBuffer buffer)
        {
            buffer.Ensure(_key.TagSize);
            _key.ReadTag(buffer.Memory.Span.Slice(0, _key.TagSize));
            buffer.Advance(_key.TagSize);
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
