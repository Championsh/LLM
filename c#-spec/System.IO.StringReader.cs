using System;
using System.Threading.Tasks;
namespace System.IO
{
    public class StringReader : TextReader
    {
        private string _s;
        private int _pos;
        private int _length;

        private int _getRandom()
        {
            return (new Random()).Next();
        }
        private bool _getBool()
        {
            return _getRandom() % 2 == 0;
        }

        public StringReader(string s)
        {
            if (s == null)
                throw new ArgumentNullException("s");
            _s = s;
            _length = s == null ? 0 : s.Length;
        }

        public override void Close()
        {
            Dispose(true);
        }

        protected override void Dispose(bool disposing)
        {
            _s = null;
            _pos = 0;
            _length = 0;
            base.Dispose(disposing);
        }
        
        public override int Read(char[] buffer, int index, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException();
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (buffer.Length - index < count)
                throw new ArgumentException();
            //if (_s == null)
            //    __Error.ReaderClosed();

            int n = _length - _pos;
            if (n > 0)
            {
                if (n > count)
                    n = count;
                _pos += n;
            }
            return n;
        }

        public override string ReadLine()
        {
            // if (_s == null)
            //     __Error.ReaderClosed();

            int i = _pos;
            bool k = _getBool();
            if (i < _length && k)
            {
                string result = _s.Substring(_pos, i - _pos);
                _pos = i + 1;
                return result;
            }
            if (i > _pos)
            {
                string result = _s.Substring(_pos, i - _pos);
                _pos = i;
                return result;
            }

            return null;
        }

        public override Task<int> ReadBlockAsync(char[] buffer, int index, int count)
        {
            if (buffer==null)
                throw new ArgumentNullException();
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (buffer.Length - index < count)
                throw new ArgumentException();

            int k = _getRandom();
            return Task.FromResult(k);
        }
 
        public override Task<int> ReadAsync(char[] buffer, int index, int count)
        {
            if (buffer==null)
                throw new ArgumentNullException();
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (buffer.Length - index < count)
                throw new ArgumentException();

            int k = _getRandom();
            return Task.FromResult(k);
        }
    }
}