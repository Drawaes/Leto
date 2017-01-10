using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using static Interop.BCrypt;
using Microsoft.Win32.SafeHandles;
using Leto.Tls13.Hash;
using Leto.Tls13.Interop.Windows;
using System.Runtime.InteropServices;

namespace Leto.Tls13.KeyExchange.Windows
{
    public class ECCurveInstance : IKeyshareInstance
    {
        private SafeBCryptAlgorithmHandle _algo;
        private bool _hasPeerKey;
        private NamedGroup _group;
        private int _keyExchangeSize;
        private SafeBCryptKeyHandle _key;
        private SafeBCryptKeyHandle _peerKey;

        internal ECCurveInstance(SafeBCryptAlgorithmHandle algo, NamedGroup group, int keyExchangeSize)
        {
            _keyExchangeSize = keyExchangeSize;
            _group = group;
            _algo = algo;
        }

        public bool HasPeerKey => _hasPeerKey;
        public int KeyExchangeSize => _keyExchangeSize;
        public NamedGroup NamedGroup => _group;

        public void Dispose()
        {
            _key?.Dispose();
        }

        public unsafe void SetPeerKey(ReadableBuffer peerKey)
        {
            if (peerKey.Length != _keyExchangeSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
            int cbKey;
            if (_group != NamedGroup.x25519 && _group != NamedGroup.x448)
            {
                peerKey = peerKey.Slice(1);
                cbKey = peerKey.Length /2;
            }
            else
            {
                peerKey = peerKey.Slice(1);
                cbKey = peerKey.Length;
            }
            GenerateKeys();
            int keyLength = peerKey.Length;
            //Now we have the point and can load the key
            var keyBuffer = stackalloc byte[keyLength + 8];
            var blobHeader = new BCRYPT_ECCKEY_BLOB();
            blobHeader.Magic = KeyBlobMagicNumber.BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
            blobHeader.cbKey = cbKey;
            Marshal.StructureToPtr(blobHeader, (IntPtr)keyBuffer, false);
            peerKey.CopyTo(new Span<byte>(keyBuffer + 8, keyLength));
            SafeBCryptKeyHandle keyHandle;
            ExceptionHelper.CheckReturnCode(BCryptImportKeyPair(_algo, IntPtr.Zero, KeyBlobType.BCRYPT_ECCPUBLIC_BLOB, out keyHandle, (IntPtr)keyBuffer, keyLength + 8, 0));
            _peerKey = keyHandle;
        }

        private void GenerateKeys()
        {
            ExceptionHelper.CheckReturnCode(BCryptGenerateKeyPair(_algo, out _key, 0, 0));
            ExceptionHelper.CheckReturnCode(BCryptFinalizeKeyPair(_key, 0));
        }

        public void WritePublicKey(ref WritableBuffer keyBuffer)
        {
            throw new NotImplementedException();
        }

        public unsafe void DeriveSecret(IHashProvider hashProvider, HashType hashType, void* salt, int saltSize, void* output, int outputSize)
        {
            throw new NotImplementedException();
        }
    }
}
