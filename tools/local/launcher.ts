#!/usr/bin/env bun

import { runLocalLauncher } from "../internal/runtime";

runLocalLauncher().catch((error) => {
    console.error(`[error] ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
});
