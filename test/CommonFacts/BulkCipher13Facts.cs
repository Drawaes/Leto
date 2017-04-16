using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Leto;
using Leto.BulkCiphers;
using Leto.RecordLayer;
using Xunit;

namespace CommonFacts
{
    public static class BulkCipher13Facts
    {
        private static readonly byte[] s_clientFinishedDecrypted = "08 00 00 02 00 00".HexToByteArray();
        private static readonly byte[] s_clientFinishedEncrypted = "f6 67 54 fb f5 02 31 3e 62 7f 1b 00 e9 a2 31 e0 4a 53 51 20 27 4e 6c".HexToByteArray();
        private static readonly byte[] s_key = "ad 19 00 5e 7f 4b 77 b6 78 26 6e 0e 2c ed 60 2d".HexToByteArray();
        private static readonly byte[] s_iv = "41 6c 48 f2 2c 0c 25 e1 bd 6a 53 0d".HexToByteArray();
        private static readonly byte[] s_frameHeader = "17 03 01 00 17".HexToByteArray();

        public static async Task DecryptClientMessage(IBulkCipherKeyProvider provider)
        {
            using (var cipher = SetIVAndKey(provider))
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_clientFinishedEncrypted);
                await writer.FlushAsync();
                var reader = await pipe.Reader.ReadAsync();
                var buffer = reader.Buffer;
                cipher.Decrypt(ref buffer, RecordType.Handshake, TlsVersion.Tls13Draft18);
                var readerSpan = buffer.ToSpan();
                Assert.Equal(s_clientFinishedDecrypted, readerSpan.Slice(0, readerSpan.Length - 1).ToArray());
                Assert.Equal(RecordType.Handshake, readerSpan.Slice(readerSpan.Length - 1).Read<RecordType>());
            }
        }

        public static async Task EncryptClientMessage(IBulkCipherKeyProvider provider)
        {
            using (var cipher = SetIVAndKey(provider))
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_clientFinishedDecrypted);
                await writer.FlushAsync();

                var reader = await pipe.Reader.ReadAsync();
                writer = pipe.Writer.Alloc();
                var buffer = reader.Buffer;
                cipher.Encrypt(ref writer, buffer, RecordType.Handshake, TlsVersion.Tls13Draft18);
                pipe.Reader.Advance(buffer.End);
                await writer.FlushAsync();

                reader = await pipe.Reader.ReadAsync();
                buffer = reader.Buffer;
                Assert.Equal(s_clientFinishedEncrypted, buffer.ToArray());
            }
        }

        private static AeadBulkCipher SetIVAndKey(IBulkCipherKeyProvider provider)
        {
            var tempIv = new byte[12];
            s_iv.CopyTo(tempIv);
            return provider.GetCipher<AeadTls13BulkCipher>(BulkCipherType.AES_128_GCM, new System.Buffers.OwnedPinnedBuffer<byte>(s_key.Concat(tempIv).ToArray()));
        }
    }
}
