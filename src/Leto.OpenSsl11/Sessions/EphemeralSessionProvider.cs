using System;
using System.Binary;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.BulkCiphers;
using Leto.ConnectionStates.SecretSchedules;
using Leto.Hashes;
using Leto.Internal;
using Leto.Sessions;

namespace Leto.OpenSsl11.Sessions
{
    public class EphemeralSessionProvider : ISessionProvider
    {
        private TimeSpan _maxTicketAge = TimeSpan.FromDays(1);
        private static readonly byte[] _ticketLabel = Encoding.ASCII.GetBytes("Ephemeral Ticket Generation");
        private ICryptoProvider _cryptoProvider;
        private ISymmetricalCipher _key;
        private BulkCipherType _cipherType;
        private Guid _keyGuid;
        private long _nounceCounter;


        public EphemeralSessionProvider(ICryptoProvider provider, BulkCipherType cipherType, SecretSchedulePool secretPool)
        {
            _cryptoProvider = provider;
            _cipherType = cipherType;
            var keyBuffer = secretPool.GetKeyBuffer();
            _key = GenerateKey(keyBuffer);
            _keyGuid = Guid.NewGuid();
        }

        /// <summary>
        /// Here we generate the key from random data, then we will use the TLS 1.3 Expand function to ensure that
        /// if there is a weakness in our randoms it is harder to reverse
        /// </summary>
        private ISymmetricalCipher GenerateKey(OwnedBuffer<byte> buffer)
        {
            //We use the crypto random function to fill the key buffer initially
            _cryptoProvider.FillWithRandom(buffer.AsSpan());
            //We use the Hkdf expand method to make it harder to exploit any weakness in the random number generator
            _cryptoProvider.HashProvider.HkdfExpandLabel(HashType.SHA512, buffer.AsSpan(), _ticketLabel, new ReadOnlySpan<byte>(), buffer.AsSpan());
            return _cryptoProvider.BulkCipherProvider.GetCipherKey(_cipherType, buffer);
        }

        public void Dispose()
        {
            _key?.Dispose();
            _key = null;
        }

        public unsafe void EncryptSessionKey(ref WritableBuffer writer, Span<byte> ticketContent)
        {
            var tagLength = 16;
            lock (_key)
            {
                var contentLength = ticketContent.Length + tagLength + sizeof(long) + sizeof(Guid);
                var nonce = System.Threading.Interlocked.Increment(ref _nounceCounter);
                writer.WriteBigEndian((ushort)contentLength);
                writer.Ensure(contentLength);

                _key.IV.Slice(4).Span.Write(nonce);
                _key.Init(KeyMode.Encryption);
                
                writer.WriteBigEndian(_keyGuid);
                writer.WriteBigEndian(_nounceCounter);

                var amountWritten = _key.Finish(ticketContent, writer.Buffer.Span);
                writer.Advance(amountWritten);
                _key.GetTag(writer.Buffer.Span.Slice(0,tagLength));
                writer.Advance(tagLength);
            }
        }

        public DateTime GetCurrentExpiry() => DateTime.UtcNow.Add(_maxTicketAge);

        public BigEndianAdvancingSpan ProcessSessionTicket(BigEndianAdvancingSpan sessionTicket)
        {
            var keyId = sessionTicket.Read<Guid>();
            if(keyId != _keyGuid)
            {
                return new BigEndianAdvancingSpan();
            }
            lock(_key)
            {
                var nounce = sessionTicket.Read<long>();
                _key.IV.Span.Slice(4).Write(nounce);
                _key.Init(KeyMode.Decryption);
                var span = sessionTicket.ToSpan();
                _key.SetTag(span.Slice(span.Length - 16));
                _key.Finish(span.Slice(0, span.Length - 16));
                return new BigEndianAdvancingSpan(span.Slice(0, span.Length - 16));
            }
        }
    }
}
