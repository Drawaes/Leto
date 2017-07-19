using System;
using System.Linq;
using System.Runtime.InteropServices;
using static Leto.Interop.LibCrypto;
using static Leto.Windows.Interop.BCrypt;

namespace RawAESTest
{
    class Program
    {
        static void Main(string[] args)
        {
            var blockSize = 64 * 1024;
            var keySize = 16;
            var ivSize = 12;
            var tag = new byte[] { 0x67, 0x81, 0xD9, 0xE8, 0xBA, 0x64, 0x18, 0xF0, 0x45, 0x12, 0xCF, 0xC0, 0xB5, 0xF6, 0xB6, 0x8D };

            var input = Enumerable.Repeat<byte>(22, blockSize).ToArray();
            var output = new byte[blockSize];
            var key = Enumerable.Repeat<byte>(77, keySize).ToArray();
            var iv = Enumerable.Repeat<byte>(33, ivSize).ToArray();
            var totalbytes = (10 * 1024 * 1024 * 1024L);
            var totalLoops = totalbytes / input.Length;

            var bytesPersec = OpenSslEncrypt(input, output, key, iv, totalLoops);
            GC.Collect();
            var bytesPerSecDec = OpenSslDecrypt(input, output, key, iv, totalLoops, tag);
            
            GC.Collect();
            var bytesPerSecCNG = CngEncrypt(input, output, key, iv, totalLoops);
            GC.Collect();
            var bytesPerSecCNGDec = CngDecrypt(input, output, key, iv, totalLoops, tag);

            Console.WriteLine($"{bytesPerSecCNG}GB/s CNG");
            Console.WriteLine($"{bytesPerSecCNGDec}GB/s CNG Decrypt");
            Console.WriteLine($"{bytesPersec}GB/s OpenSsl");
            Console.WriteLine($"{bytesPerSecDec}GB/s OpenSsl Decrypt");
            Console.WriteLine($"Correct tag is {BitConverter.ToString(GetTagForData(input, output, key, iv))}");
        }

        private static byte[] GetTagForData(byte[] input, byte[] output, byte[] key, byte[] iv)
        {
            var ctx = EVP_CIPHER_CTX_new();
            EVP_CipherInit_ex(ctx, EVP_aes_128_gcm, key, iv, Leto.Interop.LibCrypto.KeyMode.Encrypt);

            var count = EVP_CipherUpdate(ctx, input, output);
            EVP_CipherFinal_ex(ctx);
            var returnTag = new byte[16];
            EVP_CIPHER_CTX_GetTag(ctx, returnTag);
            ctx.Free();
            return returnTag;
        }

        private unsafe static double CngEncrypt(byte[] input, byte[] output, byte[] key, byte[] iv, long loops)
        {
            var total = 0L;
            var algoHandle = BCryptOpenAlgorithmProvider("AES");
            SetBlockChainingMode(algoHandle, BCRYPT_CHAIN_MODE_GCM);
            var keyHandle = BCryptImportKey(algoHandle, key);
            var ivBuffer = new byte[16];
            var tag = new byte[16];
            var mac = new byte[16];


            var sw = new System.Diagnostics.Stopwatch();
            fixed (byte* ivBufferPtr = &ivBuffer[0])
            fixed (byte* tagPtr = &tag[0])
            fixed (byte* macPtr = &mac[0])
            fixed (byte* ivPtr = &iv[0])
            {

                sw.Start();

                for (var loop = 0; loop < loops; loop++)
                {

                    var info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
                    {
                        cbNonce = iv.Length,
                        pbNonce = ivPtr,
                        cbTag = 16,
                        pbTag = tagPtr,
                        cbMacContext = 16,
                        pbMacContext = macPtr,
                        cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>(),
                        dwInfoVersion = 1,
                        dwFlags = AuthenticatedCipherModeInfoFlags.None,
                    };

                    var count = BCryptEncrypt(keyHandle, input, output, &info, ivBufferPtr);
                    total += count;
                }
            }

            sw.Stop();
            Console.WriteLine($"Time taken {sw.ElapsedMilliseconds}");
            var bytesPersec = ((total / (double)sw.ElapsedMilliseconds) * 1000) / (1024.0 * 1024.0 * 1024.0);
            return bytesPersec;
        }

        private unsafe static double CngDecrypt(byte[] input, byte[] output, byte[] key, byte[] iv, long loops, byte[] tag)
        {
            var total = 0L;
            var algoHandle = BCryptOpenAlgorithmProvider("AES");
            SetBlockChainingMode(algoHandle, BCRYPT_CHAIN_MODE_GCM);
            var keyHandle = BCryptImportKey(algoHandle, key);
            var ivBuffer = new byte[16];
            var mac = new byte[16];


            var sw = new System.Diagnostics.Stopwatch();
            fixed (byte* ivBufferPtr = &ivBuffer[0])
            fixed (byte* tagPtr = &tag[0])
            fixed (byte* macPtr = &mac[0])
            fixed (byte* ivPtr = &iv[0])
            {

                sw.Start();

                for (var loop = 0; loop < loops; loop++)
                {

                    var info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
                    {
                        cbNonce = iv.Length,
                        pbNonce = ivPtr,
                        cbTag = 16,
                        pbTag = tagPtr,
                        cbMacContext = 16,
                        pbMacContext = macPtr,
                        cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>(),
                        dwInfoVersion = 1,
                        dwFlags = AuthenticatedCipherModeInfoFlags.None,
                    };
                    var count = BCryptDecrypt(keyHandle, input, output, &info, ivBufferPtr);
                    total += count;

                }
            }
            sw.Stop();
            Console.WriteLine($"Time taken {sw.ElapsedMilliseconds}");
            var bytesPersec = ((total / (double)sw.ElapsedMilliseconds) * 1000) / (1024.0 * 1024.0 * 1024.0);
            return bytesPersec;
        }

        private static double OpenSslEncrypt(byte[] input, byte[] output, byte[] key, byte[] iv, long totalLoops)
        {
            var total = 0L;

            var sw = new System.Diagnostics.Stopwatch();
            sw.Start();

            for (var loop = 0; loop < totalLoops; loop++)
            {
                var ctx = EVP_CIPHER_CTX_new();
                EVP_CipherInit_ex(ctx, EVP_aes_128_gcm, key, iv, Leto.Interop.LibCrypto.KeyMode.Encrypt);

                var count = EVP_CipherUpdate(ctx, input, output);
                total += count;
                EVP_CipherFinal_ex(ctx);
                ctx.Free();
            }

            sw.Stop();
            Console.WriteLine($"Time taken {sw.ElapsedMilliseconds}");
            var bytesPersec = ((total / (double)sw.ElapsedMilliseconds) * 1000) / (1024.0 * 1024.0 * 1024.0);
            return bytesPersec;
        }

        private static double OpenSslDecrypt(byte[] input, byte[] output, byte[] key, byte[] iv, long totalLoops, byte[] tag)
        {
            var total = 0L;

            var sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            for (var loop = 0; loop < totalLoops; loop++)
            {
                var ctx = EVP_CIPHER_CTX_new();
                EVP_CipherInit_ex(ctx, EVP_aes_128_gcm, key, iv, Leto.Interop.LibCrypto.KeyMode.Decrypt);
                var count = EVP_CipherUpdate(ctx, output, input);
                total += count;
                EVP_CIPHER_CTX_SetTag(ctx, tag);
                EVP_CipherFinal_ex(ctx);
                ctx.Free();
            }
            sw.Stop();
            Console.WriteLine($"Time taken {sw.ElapsedMilliseconds}");
            var bytesPersec = ((total / (double)sw.ElapsedMilliseconds) * 1000) / (1024.0 * 1024.0 * 1024.0);
            return bytesPersec;
        }
    }
}
