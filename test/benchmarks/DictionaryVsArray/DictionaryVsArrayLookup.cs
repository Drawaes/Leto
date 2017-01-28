using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;

namespace DictionaryVsArray
{
    public class DictionaryVsArrayLookup
    {
        [Params(5,10,20,50,100,500)]
        public int ItemsInList { get;set;}

        private Dictionary<ushort, LittleClass> _dictionary;
        private LittleClass[] _array;
        private const int Iterations = 100000;

        [Setup]
        public void Setup()
        {
            _dictionary = new Dictionary<ushort, LittleClass>();
            _array = new LittleClass[ItemsInList];
            for(int i = 0; i < ItemsInList;i++)
            {
                var c = new LittleClass() { Value = (ushort)(i + 0x0300)};
                _array[i] = c;
                _dictionary[c.Value] = c;
            }
        }

        [Benchmark(OperationsPerInvoke = Iterations, Baseline = true)]
        public void Dictionary()
        {
            for(int i = 0; i < Iterations;i++)
            {
                var val = _dictionary[(ushort)((i % ItemsInList) + 0x0300)].Value;
            }
        }

        [Benchmark(OperationsPerInvoke = Iterations)]
        public void Array()
        {
            var a = _array;
            for(int i = 0; i < Iterations;i++)
            {
                var lookup = (ushort)((i % ItemsInList) +0x0300);
                for(int x = 0; x < a.Length;x++)
                {
                    if(a[x].Value == lookup)
                    {
                        var val = a[x].Value;
                        break;
                    }
                }
            }
        }
    }
}
