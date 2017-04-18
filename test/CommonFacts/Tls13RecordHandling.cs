using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Leto;
using Leto.BulkCiphers;
using Xunit;

namespace CommonFacts
{
    public class Tls13RecordHandling
    {
        private static readonly byte[] s_key = "ad 19 00 5e 7f 4b 77 b6 78 26 6e 0e 2c ed 60 2d ad 19 00 5e 7f 4b 77 b6 78 26 6e 0e 2c ed 60 2d".HexToByteArray();
        private static readonly byte[] s_iv = "41 6c 48 f2 2c 0c 25 e1 bd 6a 53 0d".HexToByteArray();
        private static readonly byte[] s_largeMessage = Enumerable.Repeat<byte>(10, 100).ToArray();

        public static async Task WriteHandshakeRecord(IBulkCipherKeyProvider provider)
        {
            using (var cipher = SetIVAndKey(provider))
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_largeMessage);
                await writer.FlushAsync();

                var keyPair = new KeyPair()
                {
                    ReadKey = cipher,
                    WriteKey = cipher
                };
                var recordHandler = new Leto.RecordLayer.Tls13RecordHandler(keyPair, TlsVersion.Tls13Draft18, pipe.Writer);
                recordHandler.WriteRecords(pipe.Reader, Leto.RecordLayer.RecordType.Handshake);

                var result = pipe.Reader.TryRead(out ReadResult readResult);
                Assert.True(result);
                var header = readResult.Buffer.First.Span.Read<Leto.RecordLayer.RecordHeader>();
                Assert.Equal(Leto.RecordLayer.RecordType.Application, header.RecordType);

                pipe.Reader.Advance(readResult.Buffer.End);
            }
        }

        private static AeadBulkCipher SetIVAndKey(IBulkCipherKeyProvider provider)
        {
            return provider.GetCipher<AeadTls13BulkCipher>(BulkCipherType.AES_256_GCM, new System.Buffers.OwnedPinnedBuffer<byte>(s_key.Concat(s_iv).ToArray()));
        }

        class KeyPair : IKeyPair
        {
            public AeadBulkCipher WriteKey { get; set; }
            public AeadBulkCipher ReadKey { get; set; }
        }
    }
}
