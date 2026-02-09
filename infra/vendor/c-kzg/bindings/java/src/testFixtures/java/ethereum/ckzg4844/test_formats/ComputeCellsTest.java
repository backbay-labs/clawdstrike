package ethereum.ckzg4844.test_formats;

import ethereum.ckzg4844.TestUtils;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.tuweni.bytes.Bytes;

public class ComputeCellsTest {
  public static class Input {
    private String blob;

    public byte[] getBlob() {
      return Bytes.fromHexString(blob).toArrayUnsafe();
    }
  }

  private Input input;
  private List<String> output;

  public Input getInput() {
    return input;
  }

  public byte[] getOutput() {
    if (output == null) {
      return null;
    }
    return TestUtils.flatten(
        output.stream()
            .map(Bytes::fromHexString)
            .map(Bytes::toArrayUnsafe)
            .collect(Collectors.toList())
            .toArray(byte[][]::new));
  }
}
