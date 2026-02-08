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

        _highNibble = ParseNibble(token[0], nameof(token));
        _lowNibble = ParseNibble(token[1], nameof(token));
    }

    private static int? ParseNibble(char c, string paramName)
    {
        if (c == '?')
            return null;

        if (c is (>= '0' and <= '9') or (>= 'A' and <= 'F') or (>= 'a' and <= 'f'))
            return Convert.ToInt32(c.ToString(), 16);

        throw new ArgumentException($"Invalid hex character '{c}'. Expected 0-9, A-F, a-f, or '?' for wildcard.", paramName);
    }

    public bool Matches(byte b)
    {
        int high = (b >> 4) & 0xF;
        int low = b & 0xF;
        return (!_highNibble.HasValue || _highNibble.Value == high) &&
               (!_lowNibble.HasValue || _lowNibble.Value == low);
    }
}