using System;
using System.Text;

namespace System.IO
{
    /*public class StringWriter : TextWriter
    {
        private bool _isOpen;

        public override Encoding Encoding => throw new NotImplementedException();

        public StringWriter()
        {
            _isOpen = true;
        }

        public StringWriter(IFormatProvider formatProvider)
        {
            _isOpen = true;
        }
        
        public StringWriter(StringBuilder sb) //: this(sb, CultureInfo.CurrentCulture)
        {
            if (sb == null)
                throw new ArgumentNullException();
            
            _isOpen = true;
        }

        public StringWriter(StringBuilder sb, IFormatProvider formatProvider)
        {
            if (sb == null)
                throw new ArgumentNullException();
            
            _isOpen = true;
        }

        public override void Close()
        {
            Dispose(true);
        }

        protected override void Dispose(bool disposing)
        {
            _isOpen = false;
            base.Dispose(disposing);
        }

        public override void Write(char[] buffer, int index, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException("buffer");
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (buffer.Length - index < count)
                throw new ArgumentException();

            //if (!_isOpen)
            //    __Error.WriterClosed();
        }
    }*/
}