package ethereum.ckzg4844;

public class LoadTrustedSetupParameters {

  private final byte[] g1MonomialBytes;
  private final byte[] g1LagrangeBytes;
  private final byte[] g2MonomialBytes;

  public LoadTrustedSetupParameters(
      final byte[] g1MonomialBytes, final byte[] g1LagrangeBytes, final byte[] g2MonomialBytes) {
    this.g1MonomialBytes = g1MonomialBytes;
    this.g1LagrangeBytes = g1LagrangeBytes;
    this.g2MonomialBytes = g2MonomialBytes;
  }

  public byte[] getG1MonomialBytes() {
    return g1MonomialBytes;
  }

  public byte[] getG1LagrangeBytes() {
    return g1LagrangeBytes;
  }

  public byte[] getG2MonomialBytes() {
    return g2MonomialBytes;
  }
}
