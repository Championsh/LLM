namespace System.IO
{
    public class MemoryStream : Stream
    {
        // TODO: model for Stream base class
        
        private byte[] _data = new byte[1048576];
        private int _size = 0;

        public override bool CanRead => throw new NotImplementedException();

        public override bool CanSeek => throw new NotImplementedException();

        public override bool CanWrite => throw new NotImplementedException();

        public override long Length => throw new NotImplementedException();

        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            for (int i = 0; i < count; i++)
                _data[_size + i] = buffer[offset + i];
            _size += count;
        }
        
        // TODO: CopyTo
        
        // TODO: Read
        
        // TODO: ToArray()
        
        // TODO: WriteTo
    }
}