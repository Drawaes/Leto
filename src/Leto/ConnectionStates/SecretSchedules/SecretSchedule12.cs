using System;
using System.Buffers;
using Leto.Hashes;
using static Leto.BufferExtensions;
using Leto.BulkCiphers;
using static Leto.TlsConstants;
using System.Runtime.InteropServices;
using System.IO.Pipelines;
using Leto.Sessions;
using Leto.Handshake;
using System.Binary;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedule12 : IDisposable
    {
        private OwnedBuffer<byte> _secretStore;
        private Buffer<byte> _clientRandom;
        private Buffer<byte> _serverRandom;
        private Buffer<byte> _masterSecret;
        private Buffer<byte> _clientVerify;
        private Buffer<byte> _serverVerify;
        private Server12ConnectionState _state;
        private ICryptoProvider _cryptoProvider;

        public SecretSchedule12(Server12ConnectionState state)
        {
            _state = state;
            _secretStore = state.SecureConnection.Listener.SecretSchedulePool.GetSecretBuffer();
            var memory = _secretStore.Buffer;
            _clientRandom = SliceAndConsume(ref memory, RandomLength);
            _serverRandom = SliceAndConsume(ref memory, RandomLength);
            _masterSecret = SliceAndConsume(ref memory, Tls12.MasterSecretLength);
            _clientVerify = SliceAndConsume(ref memory, VerifyDataLength);
            _serverVerify = SliceAndConsume(ref memory, VerifyDataLength);
            _cryptoProvider = state.SecureConnection.Listener.CryptoProvider;
        }

        internal ReadOnlySpan<byte> ClientRandom => _clientRandom.Span;
        internal ReadOnlySpan<byte> ServerRandom => _serverRandom.Span;
        private ISessionProvider Sessions => _state.SecureConnection.Listener.SessionProvider;

        public void SetClientRandom(Span<byte> random)
        {
            random.CopyTo(_clientRandom.Span);
            GenerateServerRandom();
        }

        private void GenerateServerRandom()
        {
            var span = _serverRandom.Span;
            var randomBytes = RandomLength - Tls12.EndOfRandomDowngradeProtection.Length;
            _cryptoProvider.FillWithRandom(span.Slice(0, randomBytes));
            span = span.Slice(randomBytes);
            //https://tlswg.github.io/tls13-spec/#rfc.section.4.1.3
            //Last 8 bytes of random are a special value to protect against downgrade attacks
            Tls12.EndOfRandomDowngradeProtection.CopyTo(span);
        }

        public void GenerateMasterSecret()
        {
            var seed = new byte[RandomLength * 2];
            _clientRandom.Span.CopyTo(seed);
            _serverRandom.Span.CopyTo(seed.Slice(RandomLength));
            _state.KeyExchange.DeriveMasterSecret(_cryptoProvider.HashProvider, _state.CipherSuite.HashType, seed, _masterSecret.Span);
            _state.KeyExchange.Dispose();
            _state.KeyExchange = null;
        }

        public bool ReadSessionTicket(Span<byte> buffer)
        {
            var advanceBuffer = Sessions.ProcessSessionTicket(new Internal.BigEndianAdvancingSpan(buffer));
            if (advanceBuffer.Length == 0)
            {
                return false;
            }
            var info = advanceBuffer.Read<SessionInfo>();
            if (info.Version != _state.RecordVersion)
            {
                return false;
            }
            _state.CipherSuite = _cryptoProvider.CipherSuites.GetCipherSuite(info.CipherSuite);
            buffer.CopyTo(_masterSecret.Span);
            return true;
        }

        public void WriteSessionTicket()
        {
            if (_state.SecureConnection.Listener.SessionProvider == null) return;
            _state.WriteHandshakeFrame((ref WritableBuffer w) =>
            {
                var currentExpiry = _state.SecureConnection.Listener.SessionProvider.GetCurrentExpiry();
                w.WriteBigEndian((uint)(DateTime.UtcNow - currentExpiry).TotalSeconds);
                var ticketBuffer = new byte[Marshal.SizeOf<SessionInfo>() + _masterSecret.Length];
                var ticketSpan = new Span<byte>(ticketBuffer);
                var info = new SessionInfo()
                {
                    CipherSuite = _state.CipherSuite.Code,
                    Timestamp = currentExpiry.Ticks,
                    Version = _state.RecordVersion
                };
                ticketSpan.WriteBigEndian(info);
                _masterSecret.CopyTo(ticketSpan.Slice(Marshal.SizeOf<SessionInfo>()));

                Sessions.EncryptSessionKey(ref w, ticketBuffer);
            }, HandshakeType.new_session_ticket);
        }
        public bool GenerateAndCompareClientVerify(Span<byte> clientVerify)
        {
            var hashResult = new byte[_state.HandshakeHash.HashSize];
            _state.HandshakeHash.InterimHash(hashResult);
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span, Tls12.Label_ClientFinished, hashResult, _clientVerify.Span);
            _state.HandshakeHash.HashData(clientVerify);
            return Internal.CompareFunctions.ConstantTimeEquals(_clientVerify.Span, clientVerify.Slice(Marshal.SizeOf<HandshakeHeader>()));
        }

        public void GenerateAndWriteServerVerify()
        {
            var hashResult = new byte[_state.HandshakeHash.HashSize];
            _state.HandshakeHash.InterimHash(hashResult);
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span, Tls12.Label_ServerFinished, hashResult, _serverVerify.Span);
            _state.WriteHandshakeFrame(WriteServerVerify, HandshakeType.finished);
        }

        private void WriteServerVerify(ref WritableBuffer writer) => writer.Write(_serverVerify.Span);

        public (AeadBulkCipher clientKey, AeadBulkCipher serverKey) GenerateKeys()
        {
            var (keySize, ivSize) = _cryptoProvider.BulkCipherProvider.GetCipherSize(_state.CipherSuite.BulkCipherType);
            var materialLength = (keySize + 4) * 2;
            var material = new byte[materialLength];
            var seedLength = _clientRandom.Length * 2;
            var seed = new byte[seedLength];
            _serverRandom.CopyTo((Span<byte>)seed);
            _clientRandom.CopyTo(seed.Slice(_serverRandom.Length));
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span, Tls12.Label_KeyExpansion, seed, material);
            var clientBuffer = _state.SecureConnection.Listener.SecretSchedulePool.GetKeyBuffer();
            var serverBuffer = _state.SecureConnection.Listener.SecretSchedulePool.GetKeyBuffer();

            material.Slice(0, keySize).CopyTo(clientBuffer.Span);
            material.Slice(keySize * 2, 4).CopyTo(clientBuffer.Span.Slice(keySize));
            material.Slice(keySize, keySize).CopyTo(serverBuffer.Span);
            material.Slice(keySize * 2 + 4, 4).CopyTo(serverBuffer.Span.Slice(keySize));
            var clientKey = _cryptoProvider.BulkCipherProvider.GetCipher<AeadTls12BulkCipher>(_state.CipherSuite.BulkCipherType, clientBuffer);
            var serverKey = _cryptoProvider.BulkCipherProvider.GetCipher<AeadTls12BulkCipher>(_state.CipherSuite.BulkCipherType, serverBuffer);
            return (clientKey, serverKey);
        }

        public void DisposeStore()
        {
            _secretStore?.Dispose();
            _secretStore = null;
            _state.HandshakeHash?.Dispose();
            _state.HandshakeHash = null;
        }

        public void Dispose()
        {
            try
            {
                _secretStore?.Dispose();
                _secretStore = null;
                GC.SuppressFinalize(this);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception disposing key {ex}");
                throw;
            }
        }

        ~SecretSchedule12()
        {
            Dispose();
        }
    }
}
