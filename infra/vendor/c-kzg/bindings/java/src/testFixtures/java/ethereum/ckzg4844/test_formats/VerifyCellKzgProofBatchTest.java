package ethereum.ckzg4844.test_formats;

import com.fasterxml.jackson.annotation.JsonProperty;
import ethereum.ckzg4844.TestUtils;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.tuweni.bytes.Bytes;

public class VerifyCellKzgProofBatchTest {
  public static class Input {
    @JsonProperty("commitments")
    private List<String> commitments;

    @JsonProperty("cell_indices")
    private List<Long> cellIndices;

    private List<String> cells;
    private List<String> proofs;

    public byte[] getCommitments() {
      return TestUtils.flatten(
          commitments.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new));
    }

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

    public byte[] getProofs() {
      return TestUtils.flatten(
          proofs.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new));
    }
  }

  private Input input;
  private Boolean output;

  public Input getInput() {
    return input;
  }

  public Boolean getOutput() {
    return output;
  }
}
