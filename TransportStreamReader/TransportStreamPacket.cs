// TransportStreamPacket.cs
using System;

// In TransportStreamReader.cs
public struct TransportStreamPacket
{
    public const int PacketSize = 188;

    // This private field stores the raw 188-byte packet data.
    private readonly byte[] _buffer;
    public byte[] Data => _buffer; // Changed to a read-only property
    public byte SyncByte { get; }
    public bool TransportErrorIndicator { get; }
    public bool PayloadUnitStartIndicator { get; }
    public byte AdaptationFieldControl { get; }
    public bool TransportPriority { get; }
    public ushort Pid { get; }
    public byte TransportScramblingControl { get; }
    public byte ContinuityCounter { get; }
    public byte[] AdaptationField { get; }
    // This is the new public property that gives read-only access to the buffer.
    public byte[] Buffer => _buffer;

    // This property calculates and returns the payload from the stored buffer.
    public byte[] Payload
    {
        get
        {
            // Add a null check to handle cases where _buffer might not be initialized properly
            if (_buffer == null)
            {
                return new byte[0]; // Return an empty payload if the buffer is null
            }

            int payloadStart = 4;
            if (AdaptationFieldControl == 2 || AdaptationFieldControl == 3)
            {
                if (_buffer.Length > 4)
                {
                    int adaptationFieldLength = _buffer[4];
                    payloadStart += 1 + adaptationFieldLength;
                }
            }
            if (payloadStart >= PacketSize)
            {
                return new byte[0]; // No payload
            }
            byte[] payload = new byte[PacketSize - payloadStart];
            Array.Copy(_buffer, payloadStart, payload, 0, payload.Length);
            return payload;
        }
    }

    // This constructor initializes all the properties by parsing the raw buffer.
    public TransportStreamPacket(byte[] buffer)
    {
        // Add a null or size check to prevent NullReferenceException when accessing the buffer
        if (buffer == null || buffer.Length < PacketSize)
        {
            // If the buffer is invalid, initialize all properties to default values
            _buffer = new byte[PacketSize];
            SyncByte = 0;
            TransportErrorIndicator = false;
            PayloadUnitStartIndicator = false;
            TransportPriority = false;
            Pid = 0;
            TransportScramblingControl = 0;
            AdaptationFieldControl = 0;
            ContinuityCounter = 0;
            AdaptationField = new byte[0];
            return;
        }

        _buffer = buffer;
        SyncByte = _buffer[0];
        TransportErrorIndicator = (_buffer[1] & 0x80) != 0;
        PayloadUnitStartIndicator = (_buffer[1] & 0x40) != 0;
        TransportPriority = (_buffer[1] & 0x20) != 0;
        Pid = (ushort)(((_buffer[1] & 0x1F) << 8) | _buffer[2]);
        TransportScramblingControl = (byte)((_buffer[3] & 0xC0) >> 6);
        AdaptationFieldControl = (byte)((_buffer[3] & 0x30) >> 4);
        ContinuityCounter = (byte)(_buffer[3] & 0x0F);

        int adaptationFieldLength = 0;
        if (AdaptationFieldControl == 2 || AdaptationFieldControl == 3)
        {
            if (_buffer.Length > 4)
            {
                adaptationFieldLength = _buffer[4];
                AdaptationField = new byte[adaptationFieldLength];
                if (adaptationFieldLength > 0)
                {
                    // Check bounds before copying
                    if (5 + adaptationFieldLength <= _buffer.Length)
                    {
                        Array.Copy(_buffer, 5, AdaptationField, 0, adaptationFieldLength);
                    }
                    else
                    {
                        AdaptationField = new byte[0]; // Invalid adaptation field length
                    }
                }
            }
        }
        else
        {
            AdaptationField = new byte[0];
        }
    }
}