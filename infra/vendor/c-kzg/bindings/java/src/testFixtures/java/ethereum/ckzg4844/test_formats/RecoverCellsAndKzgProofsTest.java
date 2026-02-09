package ethereum.ckzg4844.test_formats;

import com.fasterxml.jackson.annotation.JsonProperty;
import ethereum.ckzg4844.CellsAndProofs;
import ethereum.ckzg4844.TestUtils;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.tuweni.bytes.Bytes;

public class RecoverCellsAndKzgProofsTest {
  public static class Input {
    @JsonProperty("cell_indices")
    private List<Long> cellIndices;

    private List<String> cells;

    public long[] getCellIndices() {
      return cellIndices.stream().mapToLong(Long::longValue).toArray();
    }

    public byte[] getCells() {
      return TestUtils.flatten(
          cells.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArrayUnsafe)
              .collect(Collectors.toList())
              .toArray(byte[][]::new));
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
