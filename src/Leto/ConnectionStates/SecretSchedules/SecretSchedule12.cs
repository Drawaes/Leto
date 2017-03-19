using System;
using System.Buffers;
using System.Collections.Generic;
using static Leto.BufferExtensions;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedule12 : IDisposable
    {
        private OwnedMemory<byte> _secretStore;
        private Memory<byte> _clientRandom;
        private Memory<byte> _serverRandom;
        private Memory<byte> _masterSecret;
        private Server12ConnectionState _state;
        private ICryptoProvider _cryptoProvider;

        public SecretSchedule12(Server12ConnectionState state)
        {
            _state = state;
            _secretStore = state.SecureConnection.Listener.SecretSchedulePool.GetSecretBuffer();
            var memory = _secretStore.Memory;
            _clientRandom = SliceAndConsume(ref memory, TlsConstants.RandomLength);
            _serverRandom = SliceAndConsume(ref memory, TlsConstants.RandomLength);
            _masterSecret = SliceAndConsume(ref memory, TlsConstants.Tls12.MasterSecretLength);
            _cryptoProvider = state.SecureConnection.Listener.CryptoProvider;
        }

        public void SetClientRandom(Span<byte> random)
        {
            random.CopyTo(_clientRandom.Span);
        }

        public void GenerateMasterSecret()
        {
            var seed = new byte[TlsConstants.RandomLength * 2];
            _clientRandom.Span.CopyTo(seed);
            _serverRandom.Span.CopyTo(seed.Slice(TlsConstants.RandomLength));
            _state.Keyshare.DeriveMasterSecret(_cryptoProvider.HashProvider, _state.CipherSuite.HashType, seed, _masterSecret.Span);
            _state.Keyshare.Dispose();
            _state.Keyshare = null;
        }

        public void Dispose()
        {
            _secretStore?.Dispose();
            _secretStore = null;
            GC.SuppressFinalize(this);
        }

        ~SecretSchedule12()
        {
            Dispose();
        }
    }
}
