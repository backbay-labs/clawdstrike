import { createCuaTranslator } from "@clawdstrike/adapter-core";

export const claudeCuaTranslator = createCuaTranslator({
  providerName: "Claude",
  cuaToolNames: new Set(["computer", "computer_use", "computer.use", "computer-use"]),
  cuaToolPrefixes: ["computer_", "computer."],
  normalizeAction: (a) =>
    ({ mouse_click: "click", key_type: "type", key_press: "key", keypress: "key" }[a] ?? a),
  connectActions: new Set(["navigate", "connect"]),
  connectEventAction: "navigate",
});
