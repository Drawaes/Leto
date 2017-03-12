using Leto.RecordLayer;
using System;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Leto.BulkCiphers
{
    public sealed class AeadBulkCipher : IDisposable
    {
        private static readonly IntPtr s_zeroBuffer = Marshal.AllocHGlobal(byte.MaxValue);
        private const int AdditionalInfoHeaderSize = 13;
        private byte[] _sequence;
        private ulong _sequenceNumber;
        private IBulkCipherKey _key;
        private byte _paddingSize;

        static AeadBulkCipher()
        {
            var array = new byte[byte.MaxValue];
            Marshal.Copy(array, 0, s_zeroBuffer, array.Length);
        }

        internal AeadBulkCipher(IBulkCipherKey key)
        {
            _sequence = new byte[key.IV.Length];
            _key = key;
        }

        public byte PaddingSize { get => _paddingSize; set => _paddingSize = value; }
        public int Overhead => _key.TagSize + _paddingSize;
        public int KeySize => _key.Key.Length;
        public int IVSize => _key.IV.Length;

        public void SetKey(Span<byte> key)
        {
            key.CopyTo(_key.Key.Span);
        }

        public void SetIV(Span<byte> iv)
        {
            var localIv = _key.IV.Span;
            for (var i = 0; i < iv.Length; i++)
            {
                localIv[i] = (byte)(iv[i] ^ 0x0);
            }
        }

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
                    if (_sequence[i] > 0)
                    {
                        return;
                    }
                }
                i -= 1;
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Failed to increment sequence on Aead Cipher");
        }

        public void WriteNonce(ref WritableBuffer buffer)
        {
            buffer.Write(_key.IV.Span.Slice(4));
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

        private unsafe AdditionalInfo ReadAdditionalInfo(ref ReadableBuffer messageBuffer)
        {
            var headerSpan = messageBuffer.Slice(0, AdditionalInfoHeaderSize).ToSpan();

            var additionalInfo = new AdditionalInfo() { SequenceNumber = _sequenceNumber };
            var additionalSpan = new Span<byte>(Unsafe.AsPointer(ref additionalInfo), Marshal.SizeOf<AdditionalInfo>());
            headerSpan.Slice(0, 5).CopyTo(additionalSpan.Slice(sizeof(ulong)));
            var plainTextLength = additionalInfo.PlainTextLength - _key.TagSize - 8;
            additionalInfo.PlainTextLength = (ushort)plainTextLength;

            var nSpan = _key.IV.Span;
            headerSpan.Slice(5).CopyTo(nSpan.Slice(4));

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

        ~AeadBulkCipher()
        {
            Dispose();
        }
    }
}
