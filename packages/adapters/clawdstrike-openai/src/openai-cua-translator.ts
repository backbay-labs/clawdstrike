import { createCuaTranslator } from "@clawdstrike/adapter-core";

export const openAICuaTranslator = createCuaTranslator({
  providerName: "OpenAI",
  cuaToolNames: new Set(["computer_use", "computer.use", "computer-use", "computer"]),
  cuaToolPrefixes: ["computer_use_", "computer_use."],
});
