namespace Memlib;

public struct Wildcard
{
    private readonly int? _highNibble; // null represents wildcard
    private readonly int? _lowNibble;  // null represents wildcard

    public Wildcard(string token)
    {
        _highNibble = token[0] == '?' ? null : Convert.ToInt32(token[0].ToString(), 16);
        _lowNibble = token[1] == '?' ? null : Convert.ToInt32(token[1].ToString(), 16);
    }

    public byte? AsByte()
    {
        if (!_highNibble.HasValue || !_lowNibble.HasValue)
            return null;

        return (byte)((_highNibble.Value << 4) | _lowNibble.Value);
    }

    public bool Matches(byte b)
    {
        int high = (b >> 4) & 0xF;
        int low = b & 0xF;
        return (!_highNibble.HasValue || _highNibble.Value == high) &&
               (!_lowNibble.HasValue || _lowNibble.Value == low);
    }
}