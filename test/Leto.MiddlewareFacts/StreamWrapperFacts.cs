using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Xunit;

namespace Leto.MiddlewareFacts
{
    public class StreamWrapperFacts
    {
        [Fact]
        public void PropertiesPassThrough()
        {
            using (var innerStream = new MemoryStream())
            {
                using (var wrapper = new WindowsAuthentication.WindowsAuthStreamWrapper(innerStream, new WindowsAuthentication.WindowsAuthFeature()))
                {
                    Assert.Equal(innerStream.CanRead, wrapper.CanRead);
                    Assert.Equal(innerStream.CanWrite, wrapper.CanWrite);
                    Assert.Equal(false, wrapper.CanSeek);
                    wrapper.Flush();
                }
            }
        }
    }
}
