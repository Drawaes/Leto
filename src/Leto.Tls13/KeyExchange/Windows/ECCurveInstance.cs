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
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, $"The client key didn't match the expected length");
            }
            int cbKey;
            peerKey = peerKey.Slice(1);
            cbKey = peerKey.Length / 2;
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
            _hasPeerKey = true;
        }

        private void GenerateKeys()
        {
            if (_key != null)
            {
                return;
            }
            ExceptionHelper.CheckReturnCode(BCryptGenerateKeyPair(_algo, out _key, 0, 0));
            ExceptionHelper.CheckReturnCode(BCryptFinalizeKeyPair(_key, 0));
        }

        public unsafe void WritePublicKey(ref WritableBuffer keyBuffer)
        {
            GenerateKeys();
            var tmpBuffer = stackalloc byte[_keyExchangeSize + 8];
            int resultSize;
            ExceptionHelper.CheckReturnCode(BCryptExportKey(_key, IntPtr.Zero, KeyBlobType.BCRYPT_ECCPUBLIC_BLOB, (IntPtr)tmpBuffer, _keyExchangeSize + 8, out resultSize, 0));
            var keySpan = new Span<byte>(tmpBuffer + 8, resultSize - 8);
            keyBuffer.WriteBigEndian((byte)4);
            keyBuffer.Write(keySpan);
        }

        public unsafe void DeriveSecret(IHashProvider hashProvider, HashType hashType, void* salt, int saltSize, void* output, int outputSize)
        {
            SafeBCryptSecretHandle returnPtr;
            ExceptionHelper.CheckReturnCode(BCryptSecretAgreement(_key, _peerKey, out returnPtr, 0));
            var buffDescription = new BCryptBufferDesc();
            var bufferArray = stackalloc BCryptBuffer[2];
            var algId = System.Text.Encoding.Unicode.GetBytes(hashType.ToString().ToUpper() + "\0");
            buffDescription.pBuffers = (IntPtr)bufferArray;
            buffDescription.cBuffers = 2;
            fixed (byte* algPtr = algId)
            {
                bufferArray[0] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_HASH_ALGORITHM, cbBuffer = algId.Length, pvBuffer = (IntPtr)algPtr };
                bufferArray[1] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_HMAC_KEY, cbBuffer = saltSize, pvBuffer = (IntPtr)salt };
                int sizeOfResult;
                ExceptionHelper.CheckReturnCode(BCryptDeriveKey(returnPtr, BCRYPT_KDF_HMAC, &buffDescription, (IntPtr)output, outputSize, out sizeOfResult, 0));
                returnPtr.Dispose();
                Dispose();
            }
        }
    }
}
