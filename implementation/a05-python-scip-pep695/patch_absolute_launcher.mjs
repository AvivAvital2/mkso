import fs from "node:fs";
import path from "node:path";

const sourceRoot = process.argv[2];
if (!sourceRoot) {
    throw new Error("usage: node patch_absolute_launcher.mjs SCIP_PYTHON_SOURCE_ROOT");
}

const relativeLauncher = "packages/pyright-scip/index.js";
const launcherPath = path.join(sourceRoot, relativeLauncher);
const before = Buffer.from("#!/usr/bin/env node\n", "utf8");
const after = Buffer.from("#!/usr/local/bin/node\n", "utf8");
const noFollow = fs.constants.O_NOFOLLOW ?? 0;
const descriptor = fs.openSync(launcherPath, fs.constants.O_RDWR | noFollow);

function countOccurrences(value, needle) {
    let count = 0;
    let offset = 0;
    while (true) {
        const index = value.indexOf(needle, offset);
        if (index === -1) {
            return count;
        }
        count += 1;
        offset = index + needle.length;
    }
}

function writeAll(fileDescriptor, value) {
    let offset = 0;
    while (offset < value.length) {
        const written = fs.writeSync(
            fileDescriptor,
            value,
            offset,
            value.length - offset,
            offset
        );
        if (written <= 0) {
            throw new Error(`short write while patching ${relativeLauncher}`);
        }
        offset += written;
    }
}

try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) {
        throw new Error(`${relativeLauncher}: launcher is not a regular file`);
    }
    const original = fs.readFileSync(descriptor);
    const occurrences = countOccurrences(original, before);
    if (occurrences !== 1 || !original.subarray(0, before.length).equals(before)) {
        throw new Error(
            `${relativeLauncher}: expected one exact first-line launcher anchor, found ${occurrences}`
        );
    }

    const updated = Buffer.concat([after, original.subarray(before.length)]);
    writeAll(descriptor, updated);
    fs.ftruncateSync(descriptor, updated.length);
    fs.fsyncSync(descriptor);
} finally {
    fs.closeSync(descriptor);
}

console.log("Applied mkso absolute Node launcher patch");
