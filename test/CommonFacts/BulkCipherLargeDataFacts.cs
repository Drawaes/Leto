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
    public class BulkCipherLargeDataFacts
    {
        private static readonly byte[] s_key = "ad 19 00 5e 7f 4b 77 b6 78 26 6e 0e 2c ed 60 2d".HexToByteArray();
        private static readonly byte[] s_iv = "41 6c 48 f2 2c 0c 25 e1 bd 6a 53 0d".HexToByteArray();
        private static readonly byte[] s_largeBuffer = Enumerable.Repeat<byte>(200, 8000).ToArray();

        private static async Task DecryptClientMessage(IBulkCipherKeyProvider provider, byte[] encryptedMessage)
        {
            using (var cipher = SetIVAndKey(provider))
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(encryptedMessage);
                await writer.FlushAsync();
                var reader = await pipe.Reader.ReadAsync();
                var buffer = reader.Buffer;
                cipher.Decrypt(ref buffer, RecordType.Handshake, TlsVersion.Tls13Draft18);
                var readerSpan = buffer.ToSpan();
                Assert.Equal(s_largeBuffer, readerSpan.Slice(0, readerSpan.Length - 1).ToArray());
                Assert.Equal(RecordType.Handshake, readerSpan.Slice(readerSpan.Length - 1).Read<RecordType>());
                pipe.Reader.Advance(buffer.End);
            }
        }

        public static async Task EncryptLargeMessage(IBulkCipherKeyProvider provider)
        {
            using (var cipher = SetIVAndKey(provider))
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_largeBuffer);
                await writer.FlushAsync();

                var reader = await pipe.Reader.ReadAsync();
                writer = pipe.Writer.Alloc();
                var buffer = reader.Buffer;
                cipher.Encrypt(ref writer, buffer, RecordType.Handshake, TlsVersion.Tls13Draft18);
                pipe.Reader.Advance(buffer.End);
                await writer.FlushAsync();

                reader = await pipe.Reader.ReadAsync();
                buffer = reader.Buffer;
                var array = buffer.ToArray();
                pipe.Reader.Advance(buffer.End);
                await DecryptClientMessage(provider, array);
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
