package ethereum.ckzg4844.test_formats;

import ethereum.ckzg4844.CellsAndProofs;
import ethereum.ckzg4844.TestUtils;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.tuweni.bytes.Bytes;

public class ComputeCellsAndKzgProofsTest {
  public static class Input {
    private String blob;

    public byte[] getBlob() {
      return Bytes.fromHexString(blob).toArrayUnsafe();
    }
  }

  private Input input;
  private List<List<String>> output;

  public Input getInput() {
    return input;
  }

  public CellsAndProofs getOutput() {
    if (output == null) {
      return null;
    }
    assert output.size() == 2;
    return CellsAndProofs.of(
        TestUtils.flatten(
            output.get(0).stream()
                .map(Bytes::fromHexString)
                .map(Bytes::toArrayUnsafe)
                .collect(Collectors.toList())
                .toArray(byte[][]::new)),
        TestUtils.flatten(
            output.get(1).stream()
                .map(Bytes::fromHexString)
                .map(Bytes::toArrayUnsafe)
                .collect(Collectors.toList())
                .toArray(byte[][]::new)));
  }
}
