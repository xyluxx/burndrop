import { crc32 } from "node:zlib";
import { describe, expect, it } from "vitest";
import { zip } from "../scripts/zip.mjs";

interface Entry {
  name: string;
  method: number;
  time: number;
  date: number;
  crc: number;
  size: number;
  offset: number;
}

/** centralDirectory reads the archive the way an extractor does, from the end record backwards. */
function centralDirectory(archive: Buffer): Entry[] {
  const end = archive.length - 22;
  expect(archive.readUInt32LE(end)).toBe(0x06054b50);
  const count = archive.readUInt16LE(end + 10);
  let p = archive.readUInt32LE(end + 16);
  const entries: Entry[] = [];
  for (let i = 0; i < count; i++) {
    expect(archive.readUInt32LE(p)).toBe(0x02014b50);
    const nameLength = archive.readUInt16LE(p + 28);
    const extraLength = archive.readUInt16LE(p + 30);
    const commentLength = archive.readUInt16LE(p + 32);
    entries.push({
      name: archive.toString("utf8", p + 46, p + 46 + nameLength),
      method: archive.readUInt16LE(p + 10),
      time: archive.readUInt16LE(p + 12),
      date: archive.readUInt16LE(p + 14),
      crc: archive.readUInt32LE(p + 16),
      size: archive.readUInt32LE(p + 24),
      offset: archive.readUInt32LE(p + 42),
    });
    p += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

describe("zip", () => {
  const files = new Map<string, Buffer>([
    ["b.txt", Buffer.from("bee")],
    ["a/x.bin", Buffer.from([0, 1, 2, 255])],
    ["a/empty", Buffer.alloc(0)],
  ]);

  it("is reproducible whatever the insertion order", () => {
    const one = zip(files);
    const two = zip(new Map([...files].reverse()));
    expect(one.equals(two)).toBe(true);
  });

  it("stores sorted entries with the fixed timestamp, correct CRCs, and readable local headers", () => {
    const archive = zip(files);
    const entries = centralDirectory(archive);
    expect(entries.map((e) => e.name)).toEqual(["a/empty", "a/x.bin", "b.txt"]);
    for (const entry of entries) {
      const data = files.get(entry.name)!;
      expect(entry.method).toBe(0);
      expect(entry.time).toBe(0);
      expect(entry.date).toBe(0x21);
      expect(entry.size).toBe(data.length);
      expect(entry.crc).toBe(crc32(data));
      expect(archive.readUInt32LE(entry.offset)).toBe(0x04034b50);
      const start = entry.offset + 30 + archive.readUInt16LE(entry.offset + 26);
      expect(archive.subarray(start, start + entry.size).equals(data)).toBe(true);
    }
  });
});
