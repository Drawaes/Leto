using Leto.KeyExchanges;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Text;
using Leto.Certificates;
using Leto.Hashes;
using Leto.Windows.Interop;
using static Leto.Windows.Interop.BCrypt;
using Leto.Internal;

namespace Leto.Windows
{
    public class WindowsECCurveKeyExchange : IKeyExchange
    {
        private SafeBCryptAlgorithmHandle _handle;
        private NamedGroup _namedGroup;
        private int _keyExchangeSize;
        private SafeBCryptKeyHandle _keyPair;
        private SafeBCryptKeyHandle _peerKey;

        internal WindowsECCurveKeyExchange(SafeBCryptAlgorithmHandle handle, NamedGroup namedGroup)
        {
            _namedGroup = namedGroup;
            _handle = handle;
            switch (namedGroup)
            {
                case NamedGroup.secp256r1:
                    _keyExchangeSize = 65;
                    break;
                case NamedGroup.secp384r1:
                    _keyExchangeSize = 97;
                    break;
                case NamedGroup.secp521r1:
                    _keyExchangeSize = 133;
                    break;
                default:
                    ExceptionHelper.ThrowException(new InvalidOperationException());
                    break;
            }
        }

        public bool HasPeerKey => _peerKey != null;
        public bool RequiresServerKeyExchange => true;
        public int KeyExchangeSize => _keyExchangeSize;
        public NamedGroup NamedGroup => _namedGroup;

        public void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            using (var secretHandle = BCryptSecretAgreement(_keyPair, _peerKey))
            {
                BCryptDeriveKey(secretHandle, hashType, seed, output);
            }
            Dispose();
        }

        public void DeriveSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> salt, Span<byte> output)
        {
            using (var secret = BCryptSecretAgreement(_keyPair, _peerKey))
            {

                BCryptDeriveKey(secret, hashType, salt, output);
            }
            Dispose();
        }

        private void GenerateKeyPair()
        {
            if (_keyPair != null) return;
            _keyPair = BCryptGenerateAndFinalizeKeyPair(_handle);
        }

        public void Dispose()
        {
            _keyPair?.Dispose();
            _keyPair = null;
            _peerKey?.Dispose();
            _peerKey = null;
        }

        public void SetPeerKey(BigEndianAdvancingSpan peerKey, ICertificate certificate, SignatureScheme scheme)
        {
            peerKey = peerKey.ReadVector<byte>();
            if (peerKey.Length != _keyExchangeSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Peer key is bad");
            }
            GenerateKeyPair();
            _peerKey = BCryptImportECKey(_handle, peerKey.ToSpan());
        }

        public int WritePublicKey(Span<byte> keyBuffer)
        {
            GenerateKeyPair();
            return BCryptExportECKey(_keyPair, _keyExchangeSize, keyBuffer);
        }
    }
}
