using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Leto.Tls13.Extensions
{
    public class AlpnProvider
    {
        private readonly static Tuple<ApplicationLayerProtocolType, byte[]>[] _protocols = new Tuple<ApplicationLayerProtocolType, byte[]>[]
        {
            Tuple.Create(ApplicationLayerProtocolType.Http1_1, Encoding.ASCII.GetBytes("http/1.1")),
            Tuple.Create(ApplicationLayerProtocolType.Spdy1, Encoding.ASCII.GetBytes("spdy/1")),
            Tuple.Create(ApplicationLayerProtocolType.Spdy2, Encoding.ASCII.GetBytes("spdy/2")),
            Tuple.Create(ApplicationLayerProtocolType.Spdy3, Encoding.ASCII.GetBytes("spdy/3")),
            Tuple.Create(ApplicationLayerProtocolType.Turn, Encoding.ASCII.GetBytes("stun.turn")),
            Tuple.Create(ApplicationLayerProtocolType.Stun, Encoding.ASCII.GetBytes("stun.nat-discovery")),
            Tuple.Create(ApplicationLayerProtocolType.Http2_Tls, Encoding.ASCII.GetBytes("h2")),
            Tuple.Create(ApplicationLayerProtocolType.Http2_Tcp, Encoding.ASCII.GetBytes("h2c")),
            Tuple.Create(ApplicationLayerProtocolType.WebRtc, Encoding.ASCII.GetBytes("webrtc")),
            Tuple.Create(ApplicationLayerProtocolType.Confidential_WebRtc, Encoding.ASCII.GetBytes("c-webrtc")),
            Tuple.Create(ApplicationLayerProtocolType.Ftp, Encoding.ASCII.GetBytes("ftp"))
        };

        private readonly ApplicationLayerProtocolType[] _supportedProtocols;

        public AlpnProvider(params ApplicationLayerProtocolType[] supportedProtocols)
        {
            _supportedProtocols = supportedProtocols;
        }

        public byte[] GetBytesForProtocol(ApplicationLayerProtocolType protocol)
        {
            return _protocols[(int)protocol - 1].Item2;
        }

        public ApplicationLayerProtocolType MatchBuffer(ReadableBuffer alpn)
        {
            var bytes = alpn.ToArray();
            for (int i = 0; i < _protocols.Length; i++)
            {
                if (_protocols[i].Item2.SequenceEqual(bytes))
                {
                    if (_supportedProtocols.Contains(_protocols[i].Item1))
                    {
                        return _protocols[i].Item1;
                    }
                }
            }
            return ApplicationLayerProtocolType.None;
        }
    }
}
