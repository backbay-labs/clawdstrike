import { main } from "./cli";

main().catch((err: unknown) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
