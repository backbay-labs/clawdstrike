#!/usr/bin/env node

import { publishPackageManagerLifecycleEventToLocalEdr } from "./local-edr-publisher.js";

await publishPackageManagerLifecycleEventToLocalEdr();
