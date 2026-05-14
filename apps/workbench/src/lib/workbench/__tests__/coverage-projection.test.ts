import { describe, expect, it } from "vitest";
import { buildCoverageEntry } from "../detection-workflow/coverage-projection";

describe("coverage-projection", () => {
  it("maps OCSF file activity events into the file coverage family", () => {
    const entry = buildCoverageEntry(
      "doc-file",
      "ocsf_event",
      JSON.stringify({ class_uid: 1001, enrichments: [{ value: "T1005" }] }),
    );

    expect(entry.techniques).toEqual(["T1005"]);
    expect(entry.dataSources).toEqual(["file"]);
  });

  it("maps OCSF process activity events into process and command coverage families", () => {
    const entry = buildCoverageEntry(
      "doc-process",
      "ocsf_event",
      JSON.stringify({ class_uid: 1007, enrichments: [{ value: "T1059.001" }] }),
    );

    expect(entry.techniques).toEqual(["T1059.001"]);
    expect(entry.dataSources).toEqual(["process", "command"]);
  });
});
