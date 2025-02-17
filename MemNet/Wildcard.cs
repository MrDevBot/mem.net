namespace MemNet;

public readonly struct Wildcard(string token)
{
    private readonly int? _highNibble = token[0] == '?' ? null : Convert.ToInt32(token[0].ToString(), 16); // null represents wildcard
    private readonly int? _lowNibble = token[1] == '?' ? null : Convert.ToInt32(token[1].ToString(), 16);  // null represents wildcard

    public bool Matches(byte b)
    {
        int high = (b >> 4) & 0xF;
        int low = b & 0xF;
        return (!_highNibble.HasValue || _highNibble.Value == high) &&
               (!_lowNibble.HasValue || _lowNibble.Value == low);
    }
}