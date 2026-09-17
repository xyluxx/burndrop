// Generates icons/icon-{16,32,48,128}.png: a white lock on the brand blue,
// drawn from a few shapes with supersampled edges and encoded as PNG with
// Node's zlib. No image library is needed, and rerunning the script
// (node scripts/make-icons.mjs) reproduces the committed files.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { crc32, deflateSync } from "node:zlib";

const BRAND = [0x46, 0x5f, 0xff];
const WHITE = [0xff, 0xff, 0xff];
const SIZES = [16, 32, 48, 128];
// Samples per axis per pixel; 16 samples smooth the edges at every size.
const GRID = 4;

// Geometry in a unit square, y pointing down.
const inRoundedRect = (x, y, left, top, width, height, radius) => {
  const dx = Math.max(left + radius - x, 0, x - (left + width - radius));
  const dy = Math.max(top + radius - y, 0, y - (top + height - radius));
  return dx * dx + dy * dy <= radius * radius;
};
const inCircle = (x, y, cx, cy, r) => (x - cx) ** 2 + (y - cy) ** 2 <= r * r;

const inBackground = (x, y) => inRoundedRect(x, y, 0, 0, 1, 1, 0.22);
const inBody = (x, y) => inRoundedRect(x, y, 0.27, 0.47, 0.46, 0.34, 0.07);
// The shackle: the top half of a ring plus two legs reaching into the body.
const inShackle = (x, y) =>
  (y <= 0.45 && inCircle(x, y, 0.5, 0.45, 0.2) && !inCircle(x, y, 0.5, 0.45, 0.12)) ||
  (y > 0.45 && y <= 0.5 && (inRoundedRect(x, y, 0.3, 0.44, 0.08, 0.07, 0) || inRoundedRect(x, y, 0.62, 0.44, 0.08, 0.07, 0)));
const inKeyhole = (x, y) => inCircle(x, y, 0.5, 0.6, 0.05) || inRoundedRect(x, y, 0.475, 0.6, 0.05, 0.11, 0.02);

function colorAt(x, y) {
  if (!inBackground(x, y)) return null;
  if (inKeyhole(x, y)) return BRAND;
  if (inBody(x, y) || inShackle(x, y)) return WHITE;
  return BRAND;
}

function render(size) {
  const rgba = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let covered = 0;
      for (let sy = 0; sy < GRID; sy++) {
        for (let sx = 0; sx < GRID; sx++) {
          const color = colorAt((px + (sx + 0.5) / GRID) / size, (py + (sy + 0.5) / GRID) / size);
          if (color) {
            r += color[0];
            g += color[1];
            b += color[2];
            covered++;
          }
        }
      }
      if (covered > 0) {
        const i = (py * size + px) * 4;
        rgba[i] = Math.round(r / covered);
        rgba[i + 1] = Math.round(g / covered);
        rgba[i + 2] = Math.round(b / covered);
        rgba[i + 3] = Math.round((255 * covered) / (GRID * GRID));
      }
    }
  }
  return rgba;
}

function chunk(type, data) {
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

function png(size, rgba) {
  const stride = size * 4;
  // One filter byte (0, none) in front of every scanline.
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // colour type: RGBA
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", header), chunk("IDAT", deflateSync(raw, { level: 9 })), chunk("IEND", Buffer.alloc(0))]);
}

const out = join(dirname(dirname(fileURLToPath(import.meta.url))), "icons");
mkdirSync(out, { recursive: true });
for (const size of SIZES) {
  const file = join(out, `icon-${size}.png`);
  writeFileSync(file, png(size, render(size)));
  console.log(`wrote ${file}`);
}
