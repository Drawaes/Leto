using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using static Leto.Interop.LibCrypto;

namespace Leto.SslStream2
{
    class Program
    {
        static void Main(string[] args)
        {
            var ignore = ListenLoop();
            Console.WriteLine("Now listening on port 5000");
            Console.ReadLine();
            
        }

        private static async Task ListenLoop()
        {
            var listner = TcpListener.Create(5000);
            
            listner.Start();
            while (true)
            {
                var socket = await listner.AcceptSocketAsync();
                
                var ignore = HandleConnection(socket);
            } 
        }

        private static async Task HandleConnection(Socket socket)
        {
            await Task.Yield();
            var stream = new NetworkStream(socket, true);
            var sStream = new SslStreamPOC(stream);
            await sStream.AuthenticateAsServerAsync("C:\\code\\TLSCerts\\server.pfx", "test");
            var buffer = new byte[1000];
            while (true)
            {
                var bytes = await sStream.ReadAsync(buffer, 0, buffer.Length);

                await sStream.WriteAsync(buffer, 0, bytes);
            }
        }
    }
}
