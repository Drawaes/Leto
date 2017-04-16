using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Leto;
using Leto.BulkCiphers;
using Leto.RecordLayer;
using System.IO.Pipelines;
using Xunit;
using System.Linq;

namespace CommonFacts
{
    public static class BulkCipher12Facts
    {
        private static readonly byte[] s_clientFinishedEncrypted = "00 00 00 00 00 00 00 00 2D  77  23  0C  D7  E9  51  1C  26  76  A7  FF  9D  0B  43  A8  2C  A6  85  4B  A3  04  06  3B  6EA3  19  09  7E5F  B3  A9".HexToByteArray();
        private static readonly byte[] s_clientFinishedDecrypted = "14  00  00  0C  A2  4D  7B  D4  50  17  A3  D5  2EDF  75  55".HexToByteArray();
        private static readonly byte[] s_key = "C6  1A  42  06  56  A1  47  7D  BF  CC  45  B9  7B  96  DD  7E".HexToByteArray();
        private static readonly byte[] s_iv = "31  8B  18  E9".HexToByteArray();
        private static readonly byte[] s_frameHeader = "16  03  03  00  28".HexToByteArray();

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
                cipher.Encrypt(ref writer, buffer, RecordType.Handshake, TlsVersion.Tls12);
                pipe.Reader.Advance(buffer.End);
                await writer.FlushAsync();

                reader = await pipe.Reader.ReadAsync();
                buffer = reader.Buffer;
                Assert.Equal(s_clientFinishedEncrypted, buffer.ToArray());
            }
        }

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
                cipher.Decrypt(ref buffer, RecordType.Handshake, TlsVersion.Tls12);
                var readerSpan = buffer.ToSpan();
                Assert.Equal(s_clientFinishedDecrypted, readerSpan.ToArray());
            }
        }

        private static AeadBulkCipher SetIVAndKey(IBulkCipherKeyProvider provider)
        {
            var tempIv = new byte[12];
            s_iv.CopyTo(tempIv);
            return provider.GetCipher<AeadTls12BulkCipher>(BulkCipherType.AES_128_GCM, new System.Buffers.OwnedPinnedBuffer<byte>(s_key.Concat(tempIv).ToArray()));
        }
    }
}
