using System;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Collections;
using System.Collections.Generic;
namespace System.Collections
{
    public class BitArray: ICollection, ICloneable
    {
        private int m_length;
        private int _version;

        private const int BitsPerInt32 = 32;
        private const int BytesPerInt32 = 4;
        private const int BitsPerByte = 8;

        private int _getRandom()
        {
            return (new Random()).Next();
        }
        private bool _getBool()
        {
            return _getRandom() % 2 == 0;
        }

        public BitArray(int length, bool defaultValue)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException();
            
            m_length = length;
            _version = 0;
        }

        public BitArray(int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException();

            m_length = length;
            _version = 0;
        }

        public BitArray(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException("bytes");
            if (bytes.Length > Int32.MaxValue / BitsPerByte)
                throw new ArgumentException();
            
            m_length = bytes.Length * BitsPerByte;
            
            int j = 0;
            while (bytes.Length - j >= 4)
                j += 4;

            Contract.Assert(bytes.Length - j >= 0, "BitArray byteLength problem");
            Contract.Assert(bytes.Length - j < 4, "BitArray byteLength problem #2");
            
            _version = 0;
        }

        public BitArray(bool[] values)
        {
            if (values == null)
                throw new ArgumentNullException("values");

            m_length = values.Length;
            _version = 0;

        }

        public BitArray(int[] values)
        {
            if (values == null)
                throw new ArgumentNullException("values");
            if (values.Length > Int32.MaxValue / BitsPerInt32)
                throw new ArgumentException();

            m_length = values.Length * BitsPerInt32;
            _version = 0;
        }
        
        public BitArray(BitArray bits)
        {
            if (bits == null)
                throw new ArgumentNullException("bits");
            
            m_length = bits.m_length;
            _version = bits._version;
        }

        public bool Get(int index)
        {
            if (index < 0 || index >= m_length)
                throw new ArgumentOutOfRangeException();
            return _getBool();
        }
        
        public void Set(int index, bool value)
        {
            if (index < 0 || index >= m_length)
                throw new ArgumentOutOfRangeException();
            
            _version++;
        }
        
        public void SetAll(bool value)
        {
            _version++;
        }
        
        public BitArray And(BitArray value)
        {
            if (value == null)
                throw new ArgumentNullException("value");
            if (m_length != value.Length)
                throw new ArgumentException();
            
            _version++;
            return this;
        }

        public BitArray Or(BitArray value)
        {
            if (value == null)
                throw new ArgumentNullException("value");
            if (m_length != value.Length)
                throw new ArgumentException();

            _version++;
            return this;
        }
        
        public BitArray Xor(BitArray value)
        {
            if (value == null)
                throw new ArgumentNullException("value");
            if (m_length != value.Length)
                throw new ArgumentException();
        
            _version++;
            return this;
        }
        
        public BitArray Not()
        {
            _version++;
            return this;
        }

        public int Length
        {
            get
            {
                return m_length;
            }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException();
                
                m_length = value;
                _version++;
            }
        }

        public int Count => throw new NotImplementedException();

        public bool IsSynchronized => throw new NotImplementedException();

        public object SyncRoot => throw new NotImplementedException();

        public void CopyTo(Array array, int index)
        {
            if (array == null)
                throw new ArgumentNullException("array");
            if (index < 0)
                throw new ArgumentOutOfRangeException();
            if (array.Rank != 1)
                throw new ArgumentException();

            if (array is byte[])
            {
                int arrayLength = m_length > 0 ? (((m_length - 1) / BitsPerByte) + 1) : 0;
                if ((array.Length - index) < arrayLength)
                    throw new ArgumentException();
            }
            else if (array is bool[])
            {
                if (array.Length - index < m_length)
                    throw new ArgumentException();
            }
            else if (!(array is int[]))
                throw new ArgumentException();
        }

        public IEnumerator GetEnumerator()
        {
            throw new NotImplementedException();
        }

        public object Clone()
        {
            throw new NotImplementedException();
        }

        private class BitArrayEnumeratorSimple : IEnumerator, ICloneable
        {
            private int index;
            private int version;
            private bool currentElement;

            private int _getRandom()
            {
                return (new Random()).Next();
            }
            private bool _getBool()
            {
                return _getRandom() % 2 == 0;
            }

            internal BitArrayEnumeratorSimple(BitArray bitarray)
            {
                this.index = -1;
                version = bitarray._version;
            }
            
            public virtual bool MoveNext()
            {
                if (_getBool())
                    throw new InvalidOperationException();
                bool r = _getBool();
                return r;
            }

            public virtual Object Current
            {
                get
                {
                    if (index == -1 || _getBool())
                        throw new InvalidOperationException();
                    return currentElement;
                }
            }

            public void Reset()
            {
                if (_getBool())
                    throw new InvalidOperationException();
                index = -1;
            }

            public object Clone()
            {
                throw new NotImplementedException();
            }
        }
    }
}
