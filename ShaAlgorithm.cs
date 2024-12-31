namespace ShaHashing;

public abstract class ShaAlgorithm
{
    public abstract byte[] PadInput(byte[] input, int blockSize, int hex);
    public abstract void ProcessBlock(byte[] block, int wordSize);
    public abstract string GetHexString(bool hex);
    public abstract string GenerateKey();
    public abstract byte[] CombinedSaltInput(string input);
    public abstract byte[] CombinedSaltInput(string input, string key);
    public string Key { get; set; } = string.Empty;

    public static ShaAlgorithm Create()
    {
        return Create();
    }

    public virtual string ComputeHash(string input, bool isSHA512 = true)
    {
        int blockSize = isSHA512 ? 128 : 64;
        int wordSize = isSHA512 ? 8 : 4;
        int hex = isSHA512 ? 16 : 8;
        byte[] inputBytes = CombinedSaltInput(input);
        byte[] paddedInput = PadInput(inputBytes, blockSize, hex);
        for (int i = 0; i < paddedInput.Length / blockSize; i++)
        {
            byte[] block = new byte[blockSize];
            Array.Copy(paddedInput, i * blockSize, block, 0, blockSize);
            ProcessBlock(block, wordSize);
        }

        return GetHexString(isSHA512);
    }

    public virtual string ComputeHash(string Input, string Key, bool isSHA512 = true)
    {
        int blockSize = isSHA512 ? 128 : 64;
        int wordSize = isSHA512 ? 8 : 4;
        int hex = isSHA512 ? 16 : 8;
        byte[] inputBytes = CombinedSaltInput(Input, Key);
        byte[] paddedInput = PadInput(inputBytes, blockSize, hex);
        for (int i = 0; i < paddedInput.Length / blockSize; i++)
        {
            byte[] block = new byte[blockSize];
            Array.Copy(paddedInput, i * blockSize, block, 0, blockSize);
            ProcessBlock(block, wordSize);
        }

        return GetHexString(isSHA512);
    }
}