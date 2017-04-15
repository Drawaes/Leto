using System;
using System.Collections.Generic;
using System.Text;
using Leto.OpenSsl11;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class CryptoMaterialFacts
    {
        private OpenSslHashProvider _provider = new OpenSslHashProvider();

        //[Fact]
        public void TestPRFSha256() => CommonFacts.Prf12Facts.TestPRFSha256(_provider);

        //[Fact]
        public void TestPRFSha384() => CommonFacts.Prf12Facts.TestPRFSha384(_provider);

        //[Fact]
        public void TestPRFSha512() => CommonFacts.Prf12Facts.TestPRFSha512(_provider);

        //[Theory]
        //[InlineData(CommonFacts.HkdfFacts.BasictestcasewithSHA256)]
        //[InlineData(CommonFacts.HkdfFacts.TestwithSHA256andzerolengthsaltinfo)]
        //[InlineData(CommonFacts.HkdfFacts.TestwithSHA256andlongerinputsoutputs)]
        public void HkdfFact(string input) => CommonFacts.HkdfFacts.HkdfFact(input, _provider);
    }
}
