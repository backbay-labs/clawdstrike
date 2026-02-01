#!/usr/bin/env node
import { createCli } from './index.js';

const program = createCli();
program.parse();
