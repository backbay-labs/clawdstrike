#!/usr/bin/env node

import { publishCiAgentEnvironmentToLocalEdr } from "./ci-agent-telemetry.js";

await publishCiAgentEnvironmentToLocalEdr();
