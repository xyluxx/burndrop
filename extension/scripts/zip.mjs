// A ZIP writer for reproducible packages: store method only, entries sorted
// by name, one fixed timestamp, no extra fields, so two builds from the same
// files produce the same bytes. Node's zlib supplies the CRC-32.
import { crc32 } from "node:zlib";

// 1980-01-01 00:00:00, the earliest moment an MS-DOS timestamp can express.
const DOS_TIME = 0x0000;
const DOS_DATE = 0x0021;
const UTF8_NAMES = 0x0800;
const VERSION = 20;

function u16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
}

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}

/**
 * zip builds an archive from a Map of path (forward slashes, no leading
 * slash) to Buffer and returns the archive as a Buffer.
 */
export function zip(files) {
  const names = [...files.keys()].sort();
  if (names.length > 0xffff) {
    throw new Error("too many entries for a plain zip");
  }
  const parts = [];
  const directory = [];
  let offset = 0;
  for (const name of names) {
    const data = files.get(name);
    const nameBytes = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const local = Buffer.concat([u32(0x04034b50), u16(VERSION), u16(UTF8_NAMES), u16(0), u16(DOS_TIME), u16(DOS_DATE), u32(crc), u32(data.length), u32(data.length), u16(nameBytes.length), u16(0), nameBytes]);
    directory.push(
      Buffer.concat([u32(0x02014b50), u16(VERSION), u16(VERSION), u16(UTF8_NAMES), u16(0), u16(DOS_TIME), u16(DOS_DATE), u32(crc), u32(data.length), u32(data.length), u16(nameBytes.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), nameBytes]),
    );
    parts.push(local, data);
    offset += local.length + data.length;
    if (offset > 0xffffffff) {
      throw new Error("archive too large for a plain zip");
    }
  }
  const central = Buffer.concat(directory);
  const end = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(names.length), u16(names.length), u32(central.length), u32(offset), u16(0)]);
  return Buffer.concat([...parts, central, end]);
}
