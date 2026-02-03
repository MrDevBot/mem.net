namespace MemNet;

public readonly struct Wildcard
{
    private readonly int? _highNibble; // null represents wildcard
    private readonly int? _lowNibble;  // null represents wildcard

    public Wildcard(string token)
    {
        if (string.IsNullOrEmpty(token))
            throw new ArgumentException("Token cannot be null or empty.", nameof(token));

        if (token.Length != 2)
            throw new ArgumentException($"Token must be exactly 2 characters, got {token.Length}: '{token}'", nameof(token));

        _highNibble = token[0] == '?' ? null : Convert.ToInt32(token[0].ToString(), 16);
        _lowNibble = token[1] == '?' ? null : Convert.ToInt32(token[1].ToString(), 16);
    }

    public bool Matches(byte b)
    {
        int high = (b >> 4) & 0xF;
        int low = b & 0xF;
        return (!_highNibble.HasValue || _highNibble.Value == high) &&
               (!_lowNibble.HasValue || _lowNibble.Value == low);
    }
}