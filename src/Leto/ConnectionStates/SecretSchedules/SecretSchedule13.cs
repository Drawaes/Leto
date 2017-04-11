using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Leto.BulkCiphers;
using Leto.Hashes;
using static Leto.TlsConstants.Tls13;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedule13
    {
        private Server13ConnectionState _state;
        private ICryptoProvider _cryptoProvider;
        private OwnedBuffer<byte> _secretStore;
        private OwnedBuffer<byte> _keyStore;
        private Buffer<byte> _secret;
        private int _hashSize;
        private Buffer<byte> _remainingStore;
        private Buffer<byte> _clientTraffic;
        private Buffer<byte> _serverTraffic;
        private Buffer<byte> _finishedKey;

        public SecretSchedule13(Server13ConnectionState state, Span<byte> presharedKey)
        {
            _state = state;
            _cryptoProvider = state.SecureConnection.Listener.CryptoProvider;
            (_secretStore, _keyStore) = state.SecureConnection.Listener.SecretSchedulePool.GetSecretBuffer();
            _remainingStore = _secretStore.Buffer;
            _hashSize = _cryptoProvider.HashProvider.HashSize(_state.CipherSuite.HashType);
            _secret = GetBufferSlice(_hashSize);
            _clientTraffic = GetBufferSlice(_hashSize);
            _serverTraffic = GetBufferSlice(_hashSize);
            _finishedKey = GetBufferSlice(_hashSize);
            _cryptoProvider.HashProvider.HkdfExtract(state.CipherSuite.HashType, new Span<byte>(), presharedKey, _secret.Span);
        }

        public Span<byte> FinishedKey => _finishedKey.Span;

        public (AeadBulkCipher clientKey, AeadBulkCipher serverKey) GenerateHandshakeSecret()
        {
            _state.KeyExchange.DeriveSecret(_cryptoProvider.HashProvider, _state.CipherSuite.HashType, _secret.Span, _secret.Span);
            _state.KeyExchange.Dispose();
            _state.KeyExchange = null;

            var hash = new byte[_hashSize];
            _state.HandshakeHash.InterimHash(hash);
            ExpandLabel(_secret, Label_ClientHandshakeTrafficSecret, hash, _clientTraffic);
            ExpandLabel(_secret, Label_ServerHandshakeTrafficSecret, hash, _serverTraffic);

            var (keySize, ivSize) = _cryptoProvider.BulkCipherProvider.GetCipherSize(_state.CipherSuite.BulkCipherType);

            var clientKey = _keyStore.Buffer.Slice(0, keySize + ivSize);
            ExpandLabel(_clientTraffic, Label_TrafficIv, new Span<byte>(), clientKey.Slice(keySize));
            ExpandLabel(_clientTraffic, Label_TrafficKey, new Span<byte>(), clientKey.Slice(0, keySize));

            var serverKey = _keyStore.Buffer.Slice(0, keySize + ivSize);
            ExpandLabel(_serverTraffic, Label_TrafficIv, new Span<byte>(), serverKey.Slice(keySize));
            ExpandLabel(_serverTraffic, Label_TrafficKey, new Span<byte>(), serverKey.Slice(0, keySize));
            var cKey = _cryptoProvider.BulkCipherProvider.GetCipher<AeadTls13BulkCipher>(_state.CipherSuite.BulkCipherType, clientKey);
            var sKey = _cryptoProvider.BulkCipherProvider.GetCipher<AeadTls13BulkCipher>(_state.CipherSuite.BulkCipherType, serverKey);

            return (cKey, sKey);
        }

        private void ExpandLabel(Buffer<byte> secret, Span<byte> label, Span<byte> hash, Buffer<byte> output)
        {
            _cryptoProvider.HashProvider.HkdfExpandLabel(_state.CipherSuite.HashType, secret.Span, label, hash, output.Span);
        }

        public void GenerateServerFinishedKey()
        {
            var output = _finishedKey.Span;
            _cryptoProvider.HashProvider.HkdfExpandLabel(_state.CipherSuite.HashType, _secret.Span, Label_ServerFinishedKey, new Span<byte>(), output);
        }

        private Buffer<byte> GetBufferSlice(int size)
        {
            var buffer = _remainingStore.Slice(0, size);
            _remainingStore = _remainingStore.Slice(size);
            return buffer;
        }

        public void Dispose()
        {
            _secretStore?.Dispose();
            _secretStore = null;
            _keyStore?.Dispose();
            _keyStore = null;
            GC.SuppressFinalize(this);
        }

        ~SecretSchedule13() => Dispose();
    }
}
