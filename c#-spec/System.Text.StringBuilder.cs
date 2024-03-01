using System;
using System.Runtime.Serialization;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Threading.Tasks;

namespace System.Text
{
    public sealed class StringBuilder : ISerializable
    {
        private string stringValue = "";
        
        internal StringBuilder m_ChunkPrevious;   
        internal int m_ChunkLength;               
        internal int m_ChunkOffset;               
        internal int m_MaxCapacity = 0;

        internal const int DefaultCapacity = 16;

        private int _getRandom()
        {
            return (new Random()).Next();
        }
        private bool _getBool()
        {
            return _getRandom() % 2 == 0;
        }

        public StringBuilder (string value)
        {
            if (value == null)
                value = string.Empty;

            stringValue = value;
            m_MaxCapacity = Int32.MaxValue;
            m_ChunkOffset = 0;
            m_ChunkLength = value.Length;
        }

        public StringBuilder(string value, int capacity)
        {
            if (capacity < 0)
                throw new ArgumentOutOfRangeException();

            if (value == null)
                value = string.Empty;
            stringValue = value;

            m_MaxCapacity = Int32.MaxValue;
            if (capacity == 0)
            {
                capacity = DefaultCapacity;
            }
            if (capacity < value.Length)
                capacity = value.Length;

            m_ChunkLength = value.Length;
        }

        public StringBuilder(string value, int startIndex, int length, int capacity)
        {
            if (capacity < 0 || length < 0 || startIndex < 0)
                throw new ArgumentOutOfRangeException();

            if (value == null)
                value = string.Empty;
            if (startIndex > value.Length - length)
                throw new ArgumentOutOfRangeException();

            stringValue = value;

            m_MaxCapacity = Int32.MaxValue;
            if (capacity == 0)
            {
                capacity = DefaultCapacity;
            }
            if (capacity < length)
                capacity = length;

            m_ChunkLength = length;
        }

        public StringBuilder(int capacity, int maxCapacity)
        {
            if (capacity > maxCapacity || maxCapacity < 1 || capacity < 0)
                throw new ArgumentOutOfRangeException();

            m_MaxCapacity = maxCapacity;
        }

        private StringBuilder(SerializationInfo info, StreamingContext context)
        {
            if (info == null)
                throw new ArgumentNullException("info");
            bool k = _getBool();
            if (k)
                throw new SerializationException();
        }

        void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
        {
            if (info == null)
                throw new ArgumentNullException("info");
        }

        public int Capacity
        {
            get
            {
                int k = _getRandom();
                return k + m_ChunkOffset;
            }
            set
            {
                if (value < 0 || value > m_MaxCapacity || value < m_ChunkOffset + m_ChunkLength)
                    throw new ArgumentOutOfRangeException();
            }
        }

        public int EnsureCapacity(int capacity)
        {
            if (capacity < 0)
                throw new ArgumentOutOfRangeException();

            if (Capacity < capacity)
                Capacity = capacity;
            return Capacity;
        }

        public override string ToString()
        {
            if (m_ChunkOffset + m_ChunkLength == 0)
                return string.Empty;

            bool ex = _getBool();
            if (ex)
                throw new ArgumentOutOfRangeException();

            return stringValue;
        }

        public string ToString(int startIndex, int length)
        {
            int currentLength = this.Length;
            bool ex = _getBool();
            if (startIndex < 0 || startIndex > currentLength || length < 0 || startIndex > (currentLength - length) || ex)
                throw new ArgumentOutOfRangeException();

            return stringValue;
        }

        public int Length
        {
            get
            {
                return m_ChunkOffset + m_ChunkLength;
            }
            set
            {
                if (value < 0 || value > m_MaxCapacity)
                    throw new ArgumentOutOfRangeException();

                int originalCapacity = Capacity;

                if (value == 0 && m_ChunkPrevious == null)
                {
                    m_ChunkLength = 0;
                    m_ChunkOffset = 0;
                    Contract.Assert(Capacity >= originalCapacity, "setting the Length should never decrease the Capacity");
                    return;
                }

                Contract.Assert(Capacity >= originalCapacity, "setting the Length should never decrease the Capacity");
            }
        }

        public StringBuilder Append(char value)
        {
            m_ChunkLength = _getRandom();
            stringValue += value;
            return this;
        }

        public StringBuilder Append(char value, int repeatCount)
        {
            if (repeatCount < 0)
                throw new ArgumentOutOfRangeException();

            m_ChunkLength = _getRandom();
            stringValue += value;
            return this;
        }

        public StringBuilder Append(char[] value, int startIndex, int charCount)
        {
            if (startIndex < 0 || charCount < 0)
                throw new ArgumentOutOfRangeException();

            if (value == null)
            {
                if (startIndex == 0 && charCount == 0)
                    return this;
                throw new ArgumentNullException("value");
            }

            if (charCount > value.Length - startIndex)
                throw new ArgumentOutOfRangeException();

            stringValue += value[0];
            return this;
        }

        public StringBuilder Append(string value, int startIndex, int count)
        {
            if (startIndex < 0 || count < 0)
                throw new ArgumentOutOfRangeException();

            if (value == null)
            {
                if (startIndex == 0 && count == 0)
                    return this;
                throw new ArgumentNullException("value");
            }

            if (count == 0)
                return this;

            if (startIndex > value.Length - count)
                throw new ArgumentOutOfRangeException();

            stringValue += value;
            return this;
        }

        public StringBuilder Append(string value)
        {
            if (value == null)
                throw new ArgumentNullException("value");

            stringValue += value;
            return this;
        }

        public StringBuilder AppendLine(string value)
        {
            if (value == null)
                throw new ArgumentNullException("value");

            stringValue += value + "\n";
            return this;
        }

        public void CopyTo(int sourceIndex, char[] destination, int destinationIndex, int count)
        {
            if (destination == null)
                throw new ArgumentNullException("destination");
            if (count < 0 || destinationIndex < 0 || (uint)sourceIndex > (uint)m_ChunkOffset + (uint)m_ChunkLength)
                throw new ArgumentOutOfRangeException();
            if (destinationIndex > destination.Length - count || sourceIndex > m_ChunkOffset + m_ChunkLength - count)
                throw new ArgumentException();
            destination[0] = CSharpCodeChecker_Kostil.AnyConverter.Convert<string, char>(stringValue);
        }

        public StringBuilder Insert(int index, string value, int count)
        {
            if (count < 0 || (uint)index > (uint)m_ChunkOffset + (uint)m_ChunkLength)
                throw new ArgumentOutOfRangeException();

            int currentLength = m_ChunkOffset + m_ChunkLength;
            if (value == null || value.Length == 0 || count == 0)
                return this;

            long insertingChars = (long)value.Length * count;
            if (insertingChars > m_MaxCapacity - m_ChunkOffset - m_ChunkLength)
                throw new OutOfMemoryException();

            Contract.Assert(insertingChars + m_ChunkOffset + m_ChunkLength < Int32.MaxValue);

            stringValue += value;
            return this;
        }

        public StringBuilder Remove(int startIndex, int length)
        {
            if (length < 0 || startIndex < 0 || length > m_ChunkOffset + m_ChunkLength - startIndex)
                throw new ArgumentOutOfRangeException();

            if (m_ChunkOffset + m_ChunkLength == length && startIndex == 0)
            {
                if (m_ChunkPrevious == null)
                {
                    m_ChunkLength = 0;
                    m_ChunkOffset = 0;
                }
            }
            return this;
        }

        public StringBuilder Insert(int index, string value)
        {
            if ((uint)index > (uint)(m_ChunkOffset + m_ChunkLength))
                throw new ArgumentOutOfRangeException();

            stringValue += value;
            return this;
        }

        public StringBuilder Insert(int index, char[] value)
        {
            if ((uint)index > (uint)(m_ChunkOffset + m_ChunkLength))
                throw new ArgumentOutOfRangeException();

            stringValue += CSharpCodeChecker_Kostil.AnyConverter.Convert<char[], string>(value);
            stringValue += CSharpCodeChecker_Kostil.AnyConverter.Convert<char, string>(value[0]);
            return this;
        }

        public StringBuilder Insert(int index, char[] value, int startIndex, int charCount)
        {
            int currentLength = m_ChunkOffset + m_ChunkLength;
            if ((uint)index > (uint)currentLength)
                throw new ArgumentOutOfRangeException();

            if (value == null)
            {
                if (startIndex == 0 && charCount == 0)
                    return this;
                throw new ArgumentNullException();
            }

            if (startIndex < 0 || charCount < 0 || startIndex > value.Length - charCount)
                throw new ArgumentOutOfRangeException();

            stringValue += CSharpCodeChecker_Kostil.AnyConverter.Convert<char[], string>(value);
            stringValue += CSharpCodeChecker_Kostil.AnyConverter.Convert<char, string>(value[0]);
            return this;
        }

        public StringBuilder AppendFormat(string format, object arg0)
        {
            if (format == null)
                throw new ArgumentNullException("format");
            bool ex = _getBool();
            if (ex)
                throw new FormatException();

            stringValue += string.Format(format, arg0);
            return this;
        }

        public StringBuilder AppendFormat(string format, object arg0, object arg1)
        {
            if (format == null)
                throw new ArgumentNullException("format");
            bool ex = _getBool();
            if (ex)
                throw new FormatException();

            stringValue += string.Format(format, arg0, arg1);
            return this;
        }

        public StringBuilder AppendFormat(string format, object arg0, object arg1, object arg2)
        {
            if (format == null)
                throw new ArgumentNullException("format");
            bool ex = _getBool();
            if (ex)
                throw new FormatException();

            stringValue += string.Format(format, arg0, arg1, arg2);
            return this;
        }
        
        public StringBuilder AppendFormat(string format, params Object[] args)
        {
            if (args == null || format == null)
                throw new ArgumentNullException((format == null) ? "format" : "args");
            bool ex = _getBool();
            if (ex)
                throw new FormatException();

            stringValue += string.Format(format, args);
            return this;
        }

        public StringBuilder AppendFormat(IFormatProvider provider, string format, object arg0)
        {
            if (format == null)
                throw new ArgumentNullException("format");
            bool ex = _getBool();
            if (ex)
                throw new FormatException();

            stringValue += string.Format(format, arg0);
            return this;
        }

        public StringBuilder AppendFormat(IFormatProvider provider, string format, object arg0, object arg1)
        {
            if (format == null)
                throw new ArgumentNullException("format");
            bool ex = _getBool();
            if (ex)
                throw new FormatException();

            stringValue += string.Format(format, arg0, arg1);
            return this;
        }

        public StringBuilder AppendFormat(IFormatProvider provider, string format, object arg0, object arg1, object arg2)
        {
            if (format == null)
                throw new ArgumentNullException("format");
            bool ex = _getBool();
            if (ex)
                throw new FormatException();

            stringValue += string.Format(format, arg0, arg1, arg2);
            return this;
        }

        public StringBuilder AppendFormat(IFormatProvider provider, string format, params Object[] args)
        {
            if (args == null || format == null)
                throw new ArgumentNullException((format == null) ? "format" : "args");
            bool ex = _getBool();
            if (ex)
                throw new FormatException();

            stringValue += string.Format(format, args);
            return this;
        }

        private static void FormatError()
        {
            throw new FormatException();
        }

        public StringBuilder Replace(string oldValue, string newValue, int startIndex, int count)
        {
            int currentLength = m_ChunkOffset + m_ChunkLength;
            if ((uint)startIndex > (uint)currentLength || count < 0 || startIndex > currentLength - count)
                throw new ArgumentOutOfRangeException();
            if (oldValue == null)
                throw new ArgumentNullException("oldValue");
            if (oldValue.Length == 0)
                throw new ArgumentException();

            stringValue += newValue;
            return this;
        }

        public StringBuilder Replace(char oldChar, char newChar)
        {
            int currentLength = m_ChunkOffset + m_ChunkLength;
            if (currentLength < 0)
                throw new ArgumentOutOfRangeException();

            stringValue += newChar;
            return this;
        }

        public StringBuilder Replace(char oldChar, char newChar, int startIndex, int count)
        {
            int currentLength = m_ChunkOffset + m_ChunkLength;
            if ((uint)startIndex > (uint)currentLength || count < 0 || startIndex > currentLength - count)
                throw new ArgumentOutOfRangeException();

            stringValue += newChar;
            return this;
        }

        private StringBuilder _getDefault()
        {
            return null;
        }

        public unsafe StringBuilder Append(char* value, int valueCount)
        {
            if (valueCount < 0)
                throw new ArgumentOutOfRangeException();
            if (value == null)
                throw new ArgumentNullException();

            //stringValue += CSharpCodeChecker_Kostil.AnyConverter.Convert<char*, string>(value);
            stringValue += CSharpCodeChecker_Kostil.AnyConverter.Convert<char, string>(*value);
            return this;
        }
    }
}