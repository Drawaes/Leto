using Leto.RecordLayer;
using System;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class BulkCipherFacts
    {
        static readonly string s_firstClientMessagePlainTextHex = "1400000c8191bf7202def7d2434aed99";
        static readonly RecordType s_firstClientMessageRecordType = RecordType.Handshake;
        static readonly ushort s_TlsVersion = 0x0303;
        static readonly string s_firstClientMessageEncryptedHex = "1603030028 709ad3637bfd4804 43e7ce25ec6fdf9b35b89f76e5ecaa27   477c78d65a770f08e4bb29689e3209fe";
        static readonly string s_keyMaterialHex = "A7F645C1C5B8185A89DCAFBD6F1D31F96F802469CF43BACD30357A561328A8413DEAB024DAEAE8223B0ADE45BD89EF43594EDF8A322217BF0A352478F583AC54634A4DFDF697D69D";
        static readonly byte[] s_keyMaterial = StringToByteArray(s_keyMaterialHex);
        static readonly byte[] s_firstClientMessagePlainText = StringToByteArray(s_firstClientMessagePlainTextHex);
        static readonly byte[] s_firstClientMessageEncrypted = StringToByteArray(s_firstClientMessageEncryptedHex);

        [Fact]
        public async Task DecryptClientMessage()
        {
            var provider = new BulkCipher.OpenSslBulkKeyProvider();
            var cipher = provider.GetCipher(BulkCipher.BulkCipherType.AES_256_GCM);
            var key = s_keyMaterial.Slice(0, cipher.KeySize);
            var iv = s_keyMaterial.Slice(cipher.KeySize * 2, 4);
            var tempIv = new byte[12];
            for (int i = 0; i < iv.Length; i++)
            {
                tempIv[i] = (byte)(iv[i] ^ 0x00);
            }

            cipher.SetKey(key);
            cipher.SetIV(iv);

            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_firstClientMessageEncrypted);
                await writer.FlushAsync();
                var reader = await pipe.Reader.ReadAsync();
                var buffer = reader.Buffer;
                cipher.Decrypt(ref buffer, true);
                var readerSpan = reader.Buffer.ToSpan();
            }
        }

        public static byte[] StringToByteArray(String hex)
        {
            hex = string.Join("", hex.Where(c => !char.IsWhiteSpace(c)));
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

//        >>> ??? [length 0005]
//    16 03 03 00 20
//>>> TLS 1.2Handshake[length 0010], Finished
//    


//read from 0x2923f5650d0 [0x2923f5d41b3] (5 bytes => 5 (0x5))
//0000 - 16 03 03                                          ...
//0005 - <SPACES/NULS>
//<<< ??? [length 0005]
//    16 03 03 00 20
//read from 0x2923f5650d0 [0x2923f5d41b8] (32 bytes => 32 (0x20))
//0000 - 44 51 07 ca 5b 26 fc 66-69 a5 6b 49 48 fb 11 47   DQ..[&.fi.kIH..G
//0010 - ca c5 b2 a3 1d ea 62 25 - f2 46 d8 c2 c1 8c 57 b3......b %.F....W.
//<<< TLS 1.2Handshake[length 0010], Finished
//    14 00 00 0c c3 f7 1e 7d a3 00 87 a0 21 61 8f ab
//-- -

//Length: 72 bytes
//    Keying material: 
    }
}
