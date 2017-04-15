using System;
using System.Collections.Generic;
using System.Text;
using Leto.Handshake.Extensions;
using Leto.Internal;
using Xunit;

namespace Leto.ProtocolFacts
{
    public class AlpnFacts
    {
        private static byte[] _httpOneAndTwoWithTls = new byte[] { 0x00, 0x10, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x02, 0x68, 0x32, 0x03, 0x68, 0x32, 0x63 };
        private static byte[] _badVectorLength = new byte[] { 0xdd, 0xaa, 0x00 };

        //[Fact]
        public void ServerPriorityUsedFact()
        {
            var provider = new ApplicationLayerProtocolProvider(true, ApplicationLayerProtocolType.Http2_Tls, ApplicationLayerProtocolType.Http1_1);
            var selectedProtocol = provider.ProcessExtension(new BigEndianAdvancingSpan(_httpOneAndTwoWithTls));
            Assert.Equal(ApplicationLayerProtocolType.Http2_Tls, selectedProtocol);
        }

        //[Fact]
        public void ClientPriorityUsedFact()
        {
            var provider = new ApplicationLayerProtocolProvider(false, ApplicationLayerProtocolType.Http2_Tls, ApplicationLayerProtocolType.Http1_1);
            var selectedProtocol = provider.ProcessExtension(new BigEndianAdvancingSpan(_httpOneAndTwoWithTls));
            Assert.Equal(ApplicationLayerProtocolType.Http1_1, selectedProtocol);
        }

        //[Fact]
        public void NoProtocolMatchesFact()
        {
            var provider = new ApplicationLayerProtocolProvider(false, ApplicationLayerProtocolType.Spdy2);
            Assert.Throws<Alerts.AlertException>(() =>
            {
                var selectedProtocol = provider.ProcessExtension(new BigEndianAdvancingSpan(_httpOneAndTwoWithTls));
            });
        }

        //[Fact]
        public void InvalidVectorLength()
        {
            var provider = new ApplicationLayerProtocolProvider(false, ApplicationLayerProtocolType.Spdy2);
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                var selectedProtocol = provider.ProcessExtension(new BigEndianAdvancingSpan(_badVectorLength));
            });
        }
    }
}
