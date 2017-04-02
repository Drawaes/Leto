using Leto.Windows;
using System;
using System.IO.Pipelines;
using System.Net;
using System.Text;

namespace SocketServer
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var factory = new PipeFactory())
            using (var listener = new System.IO.Pipelines.Networking.Sockets.SocketListener())
            using (var secureListener = new WindowsSecurePipeListener(Data.Certificates.RSACertificate))
            {
                listener.OnConnection(async (conn) =>
                {
                    var pipe = await secureListener.CreateConnection(conn);
                    Console.WriteLine("Handshake Done");
                    var writer = pipe.Output.Alloc();
                    writer.WriteBigEndian<long>(0);
                    await writer.FlushAsync();
                    pipe.Output.Complete();
                    Console.WriteLine("Connection Done");
                    
                });
                listener.Start(new IPEndPoint(IPAddress.Any, 443));
                Console.ReadLine();
            }
        }
    }
}