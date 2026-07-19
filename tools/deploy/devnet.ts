#!/usr/bin/env bun

import { runDevnetDeployment } from "../internal/runtime";

runDevnetDeployment().catch((error) => {
    console.error(`[error] ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
});
