using System.Text;

namespace ShaHashing;

public class ShaImplement : SHA
{
    private static readonly ulong[] K64 = new ulong[]
    {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

    private static readonly uint[] K32 = new uint[]
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private static ulong[] H64 = new ulong[]
    {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };

    private static uint[] H32 = new uint[]
    {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    private byte[] hashKey { get; set; } = new byte[0];

    private void Initialize()
    {
        Shuffle(hashKey);
        string base64Key = Convert.ToBase64String(hashKey);
        Key = base64Key.Length > 16 ? base64Key.Substring(0, 16) : base64Key.PadRight(32, '!');
    }

    private void Shuffle(byte[] array)
    {
        Random random = new Random();
        int n = array.Length;
        while (n > 1)
        {
            n--;
            int k = random.Next(n + 1);
            byte value = array[k];
            array[k] = array[n];
            array[n] = value;
        }
    }

    public override byte[] CombinedSaltInput(string input)
    {
        Key = GenerateKey();
        Initialize();
        string combinedInput = input + Key;
        byte[] inputBytes = Encoding.UTF8.GetBytes(combinedInput);
        return inputBytes;
    }

    public override byte[] CombinedSaltInput(string input, string key)
    {
        string combinedInput = input + key;
        byte[] inputBytes = Encoding.UTF8.GetBytes(combinedInput);
        return inputBytes;
    }

    public override string GetHexString(bool isSHA512)
    {
        StringBuilder hex = new StringBuilder();
        bool check = isSHA512 ? true : false;
        if (check)
        {
            foreach (var h in H64)
            {
                hex.AppendFormat("{0:x16}", h);
            }
        }
        else
        {
            foreach (var h in H32)
            {
                hex.AppendFormat("{0:x8}", h);
            }
        }

        return hex.ToString();
    }

    public override byte[] PadInput(byte[] input, int blockSize, int hex)
    {
        int originalLength = input.Length;
        int paddingLength = blockSize - ((originalLength + hex) % blockSize);
        byte[] paddedInput = new byte[originalLength + paddingLength + hex];
        Array.Copy(input, paddedInput, originalLength);
        paddedInput[originalLength] = 0x80;
        ulong messageLength = (ulong)(originalLength * 8);
        for (int i = 0; i < hex; i++)
        {
            paddedInput[paddedInput.Length - 1 - i] = (byte)(messageLength >> (8 * i) & 0xFF);
        }

        return paddedInput;
    }

    public override void ProcessBlock(byte[] block, int wordSize)
    {
        if (wordSize == 4)
            ProcessBlock32(block);
        else
            ProcessBlock64(block);
    }

    private void ProcessBlock64(byte[] block)
    {
        byte[] W = new byte[640];
        for (int i = 0; i < 16; i++)
        {
            Array.Copy(block, i * 8, W, i * 8, 8);
        }

        for (int i = 16; i < 80; i++)
        {
            ulong s0 = Rotate(BitConverter.ToUInt64(W, (i - 15) * 8), 1) ^
                       Rotate(BitConverter.ToUInt64(W, (i - 15) * 8), 8) ^
                       (BitConverter.ToUInt64(W, (i - 15) * 8) >> 7);
            ulong s1 = Rotate(BitConverter.ToUInt64(W, (i - 2) * 8), 19) ^
                       Rotate(BitConverter.ToUInt64(W, (i - 2) * 8), 61) ^ (BitConverter.ToUInt64(W, (i - 2) * 8) >> 6);
            ulong W_i = BitConverter.ToUInt64(W, (i - 16) * 8) + s0 + BitConverter.ToUInt64(W, (i - 7) * 8) + s1;
            BitConverter.GetBytes(W_i).CopyTo(W, i * 8);
        }

        ulong a, b, c, d, e, f, g, h;
        a = H64[0];
        b = H64[1];
        c = H64[2];
        d = H64[3];
        e = H64[4];
        f = H64[5];
        g = H64[6];
        h = H64[7];
        for (int i = 0; i < 80; i++)
        {
            ulong S1 = Rotate(e, 14) ^ Rotate(e, 18) ^ Rotate(e, 41);
            ulong ch = (e & f) ^ (~e & g);
            ulong temp1 = h + S1 + ch + K64[i] + BitConverter.ToUInt64(W, i * 8);
            ulong S0 = Rotate(a, 28) ^ Rotate(a, 34) ^ Rotate(a, 39);
            ulong maj = (a & b) ^ (a & c) ^ (b & c);
            ulong temp2 = S0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        H64[0] += a;
        H64[1] += b;
        H64[2] += c;
        H64[3] += d;
        H64[4] += e;
        H64[5] += f;
        H64[6] += g;
        H64[7] += h;
    }

    private void ProcessBlock32(byte[] block)
    {
        byte[] W = new byte[256];
        for (int i = 0; i < 16; i++)
        {
            Array.Copy(block, i * 4, W, i * 4, 4);
        }

        for (int i = 16; i < 64; i++)
        {
            uint s0 = (uint)(Rotate(BitConverter.ToUInt32(W, (i - 15) * 4), 7) ^
                             Rotate(BitConverter.ToUInt32(W, (i - 15) * 4), 18) ^
                             (BitConverter.ToUInt32(W, (i - 15) * 4) >> 3));
            uint s1 = (uint)(Rotate(BitConverter.ToUInt32(W, (i - 2) * 4), 17) ^
                             Rotate(BitConverter.ToUInt32(W, (i - 2) * 4), 19) ^
                             (BitConverter.ToUInt32(W, (i - 2) * 4) >> 10));
            uint W_i = (uint)(BitConverter.ToUInt32(W, (i - 16) * 4) + s0 + BitConverter.ToUInt32(W, (i - 7) * 4) + s1);
            BitConverter.GetBytes(W_i).CopyTo(W, i * 4);
        }

        uint a, b, c, d, e, f, g, h;
        a = H32[0];
        b = H32[1];
        c = H32[2];
        d = H32[3];
        e = H32[4];
        f = H32[5];
        g = H32[6];
        h = H32[7];
        for (int i = 0; i < 64; i++)
        {
            uint S1 = (uint)(Rotate(e, 14) ^ Rotate(e, 18) ^ Rotate(e, 41));
            uint ch = (e & f) ^ (~e & g);
            uint temp1 = (uint)(h + S1 + ch + K32[i] + W[i]);
            uint S0 = (uint)(Rotate(a, 28) ^ Rotate(a, 34) ^ Rotate(a, 39));
            uint maj = (a & b) ^ (a & c) ^ (b & c);
            uint temp2 = S0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        H32[0] += (uint)a;
        H32[1] += (uint)b;
        H32[2] += (uint)c;
        H32[3] += (uint)d;
        H32[4] += (uint)e;
        H32[5] += (uint)f;
        H32[6] += (uint)g;
        H32[7] += (uint)h;
    }

    private static ulong Rotate(ulong value, int shift)
    {
        return (value >> shift) | (value << (64 - shift));
    }

    public override string GenerateKey()
    {
        string key = DateTime.Now.ToString("yyyyHHmmffddMMssffff");
        hashKey = Encoding.UTF8.GetBytes(key);
        string base64Key = Convert.ToBase64String(hashKey);
        return Key = base64Key.Length > 23 ? base64Key.Substring(0, 23) : base64Key.PadRight(23, '=');
    }
}