namespace ShaHashing;

public abstract class SHA : ShaAlgorithm
{
    public new static SHA Create() => new ShaImplement();
}