using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.IO.Pipelines.Networking.Sockets;
using System.Net;
using System.Net.Security;
using System.Text;
using System.Threading.Tasks;

namespace SocketServer
{
    public class RawSocketHttpServerSample : RawHttpServerSampleBase
    {
        public RawSocketHttpServerSample(string filename)
            :base(filename)
        {

        }

        public SocketListener Listener { get; private set; }

        private PipeFactory _factory = new PipeFactory();

        protected override Task Start(IPEndPoint ipEndpoint)
        {
            Listener = new SocketListener();
            Listener.OnConnection(async connection => { await ProcessConnection(connection); });
                        
            Listener.Start(ipEndpoint);
            return Task.CompletedTask;
        }

        protected override Task Stop()
        {
            Listener.Dispose();
            return Task.CompletedTask;
        }
    }
}
