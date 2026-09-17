import { describe, expect, it } from "vitest";

import {
  EnvelopeError,
  MAX_NAME_LEN,
  MAX_TEXT_LEN,
  decodeEnvelope,
  encodeEnvelope,
  parseRfc3339,
  quoteJsonGo,
  revealAad,
  runeCount,
  secretBytes,
  secretField,
  validateEnvelope,
  validateName,
  validateRetention,
  validateText,
  type Envelope,
} from "../src/index.js";
import { bytesEqual, text, utf8 } from "./helpers.js";

const reveal: Envelope = { v: 1, type: "reveal", name: "staging-db-url", format: "text", secret: "postgres://example" };
const drop: Envelope = {
  v: 1,
  type: "drop",
  name: "openai-api-key",
  purpose: "Call the OpenAI API",
  storage: "macOS Keychain",
  retention: "until-revoked",
  fingerprint: "7f4e-3996-5f9b-d725",
  format: "text",
  secret: "sk-live-0123456789abcdef",
};

const NBSP = String.fromCharCode(0xa0);
const DEL = String.fromCharCode(0x7f);
const NUL = String.fromCharCode(0);
const LINE_SEP = String.fromCharCode(0x2028);
const LONE_SURROGATE = String.fromCharCode(0xd800);

describe("validateName", () => {
  it("accepts ordinary and unicode names up to 100 code points", () => {
    validateName("openai-api-key");
    validateName("clé API");
    validateName("é".repeat(MAX_NAME_LEN));
    validateName("a b");
    validateName("key\u{1F511}");
    validateName("\u{1F511}key");
  });

  it("rejects empty, long, padded, and control names", () => {
    expect(() => validateName("")).toThrow(EnvelopeError);
    expect(() => validateName("a".repeat(MAX_NAME_LEN + 1))).toThrow(EnvelopeError);
    expect(() => validateName("é".repeat(MAX_NAME_LEN + 1))).toThrow(EnvelopeError);
    expect(() => validateName(" name")).toThrow(EnvelopeError);
    expect(() => validateName("name ")).toThrow(EnvelopeError);
    expect(() => validateName("name\t")).toThrow(EnvelopeError);
    expect(() => validateName(NBSP + "name")).toThrow(EnvelopeError);
    expect(() => validateName("name" + LINE_SEP)).toThrow(EnvelopeError);
    expect(() => validateName("a" + NUL + "b")).toThrow(EnvelopeError);
    expect(() => validateName("a\nb")).toThrow(EnvelopeError);
    expect(() => validateName("a" + DEL + "b")).toThrow(EnvelopeError);
    expect(() => validateName("a" + LONE_SURROGATE)).toThrow(EnvelopeError);
  });
});

describe("validateText", () => {
  it("accepts up to 200 code points with newlines", () => {
    validateText("purpose", "");
    validateText("purpose", "line 1\nline 2");
    validateText("purpose", "é".repeat(MAX_TEXT_LEN));
  });

  it("rejects long text and control characters other than newline", () => {
    expect(() => validateText("purpose", "a".repeat(MAX_TEXT_LEN + 1))).toThrow(/purpose longer/);
    expect(() => validateText("storage", "a\tb")).toThrow(/storage contains a control character/);
    expect(() => validateText("purpose", "a\rb")).toThrow(EnvelopeError);
    expect(() => validateText("purpose", "a" + DEL)).toThrow(EnvelopeError);
    expect(() => validateText("purpose", LONE_SURROGATE)).toThrow(/not valid UTF-8/);
  });
});

describe("validateRetention and parseRfc3339", () => {
  it("accepts the three policies", () => {
    validateRetention("session");
    validateRetention("until-revoked");
    validateRetention("until:2027-03-04T05:06:07Z");
    validateRetention("until:2027-03-04T05:06:07.123Z");
    validateRetention("until:2027-03-04T05:06:07+02:00");
    validateRetention("until:2027-02-29T00:00:00Z".replace("2027", "2028"));
  });

  it("rejects other policies and malformed dates", () => {
    for (const bad of [
      "",
      "forever",
      "until",
      "until:",
      "until:2027-03-04",
      "until:2027-03-04 05:06:07Z",
      "until:2027-03-04t05:06:07Z",
      "until:2027-03-04T05:06:07z",
      "until:2027-03-04T05:06:07",
      "until:2027-03-04T05:06:07+0200",
      "until:2027-02-29T00:00:00Z",
      "until:2027-13-01T00:00:00Z",
      "until:2027-04-31T00:00:00Z",
      "until:2027-03-04T24:00:00Z",
      "until:2027-03-04T05:60:00Z",
      "until:2027-03-04T05:06:60Z",
      "until:2027-03-04T05:06:07+24:00",
      "until:2027-03-04T05:06:07+02:60",
      "until:2027-03-04T05:06:07.Z",
      "Until-revoked",
    ]) {
      expect(() => validateRetention(bad), bad).toThrow(EnvelopeError);
    }
  });

  it("parses offsets and fractions", () => {
    expect(parseRfc3339("2027-03-04T05:06:07Z")?.toISOString()).toBe("2027-03-04T05:06:07.000Z");
    expect(parseRfc3339("2027-03-04T05:06:07.5Z")?.toISOString()).toBe("2027-03-04T05:06:07.500Z");
    expect(parseRfc3339("2027-03-04T05:06:07+02:00")?.toISOString()).toBe("2027-03-04T03:06:07.000Z");
    expect(parseRfc3339("2027-03-04T05:06:07-02:30")?.toISOString()).toBe("2027-03-04T07:36:07.000Z");
    expect(parseRfc3339("2000-02-29T00:00:00Z")).toBeDefined();
    expect(parseRfc3339("1900-02-29T00:00:00Z")).toBeUndefined();
    expect(parseRfc3339("nope")).toBeUndefined();
  });
});

describe("validateEnvelope", () => {
  it("accepts valid drop and reveal envelopes", () => {
    validateEnvelope(drop);
    validateEnvelope(reveal);
    validateEnvelope({ ...drop, purpose: undefined, storage: undefined });
    validateEnvelope({ ...drop, purpose: "", storage: "" });
    validateEnvelope({ ...reveal, format: "base64", secret: "AAECA_r7_P3-_w" });
    validateEnvelope({ ...reveal, secret: "" });
    validateEnvelope({ ...reveal, purpose: "", storage: "", retention: "", fingerprint: "" });
  });

  it("rejects each rule violation", () => {
    const cases: [string, Envelope][] = [
      ["version 0", { ...reveal, v: 0 }],
      ["version 2", { ...reveal, v: 2 }],
      ["type", { ...reveal, type: "share" as "reveal" }],
      ["format", { ...reveal, format: "hex" as "text" }],
      ["empty name", { ...reveal, name: "" }],
      ["drop without retention", { ...drop, retention: undefined }],
      ["drop bad retention", { ...drop, retention: "forever" }],
      ["drop without fingerprint", { ...drop, fingerprint: undefined }],
      ["drop bad fingerprint", { ...drop, fingerprint: "7F4E-3996-5F9B-D725" }],
      ["drop short fingerprint", { ...drop, fingerprint: "7f4e-3996-5f9b" }],
      ["reveal with purpose", { ...reveal, purpose: "p" }],
      ["reveal with storage", { ...reveal, storage: "s" }],
      ["reveal with retention", { ...reveal, retention: "session" }],
      ["reveal with fingerprint", { ...reveal, fingerprint: "0000-0000-0000-0000" }],
      ["base64 secret not canonical", { ...reveal, format: "base64", secret: "AB" }],
      ["base64 secret with padding", { ...reveal, format: "base64", secret: "AA==" }],
      ["text secret not well formed", { ...reveal, secret: "a" + LONE_SURROGATE }],
      ["long purpose", { ...drop, purpose: "a".repeat(201) }],
      ["control in storage", { ...drop, storage: "a\tb" }],
    ];
    for (const [name, env] of cases) {
      expect(() => validateEnvelope(env), name).toThrow(EnvelopeError);
    }
  });
});

describe("encodeEnvelope", () => {
  it("produces Go's compact JSON without HTML escaping", () => {
    expect(text(encodeEnvelope(reveal))).toBe('{"v":1,"type":"reveal","name":"staging-db-url","format":"text","secret":"postgres://example"}');
    expect(text(encodeEnvelope(drop))).toBe(
      '{"v":1,"type":"drop","name":"openai-api-key","purpose":"Call the OpenAI API","storage":"macOS Keychain","retention":"until-revoked","fingerprint":"7f4e-3996-5f9b-d725","format":"text","secret":"sk-live-0123456789abcdef"}',
    );
    // omitempty: empty drop metadata is left out.
    expect(text(encodeEnvelope({ ...drop, purpose: "", storage: "" }))).toBe(
      '{"v":1,"type":"drop","name":"openai-api-key","retention":"until-revoked","fingerprint":"7f4e-3996-5f9b-d725","format":"text","secret":"sk-live-0123456789abcdef"}',
    );
  });

  it("escapes strings exactly like encoding/json with SetEscapeHTML(false)", () => {
    const BS = String.fromCharCode(92);
    const secret = 'päss "quoted" <tag> & done ' + BS + " tab\tnl\nCR\rBS\bFF\f" + String.fromCharCode(1) + LINE_SEP + String.fromCharCode(0x2029) + DEL + "\u{1F511}";
    const encoded = text(encodeEnvelope({ ...reveal, secret }));
    const expected =
      '{"v":1,"type":"reveal","name":"staging-db-url","format":"text","secret":"päss ' +
      BS +
      '"quoted' +
      BS +
      '" <tag> & done ' +
      BS +
      BS +
      " tab" +
      BS +
      "tnl" +
      BS +
      "nCR" +
      BS +
      "rBS" +
      BS +
      "bFF" +
      BS +
      "f" +
      BS +
      "u0001" +
      BS +
      "u2028" +
      BS +
      "u2029" +
      DEL +
      "\u{1F511}" +
      '"}';
    expect(encoded).toBe(expected);
    expect(decodeEnvelope(utf8(encoded)).secret).toBe(secret);
    // The HTML-escaping variant is what json.Marshal produces by default.
    expect(quoteJsonGo("<a>&b", true)).toBe('"' + BS + "u003ca" + BS + "u003e" + BS + 'u0026b"');
  });

  it("validates before encoding", () => {
    expect(() => encodeEnvelope({ ...reveal, name: "" })).toThrow(EnvelopeError);
  });
});

describe("decodeEnvelope", () => {
  it("round trips and treats null fields as absent", () => {
    expect(decodeEnvelope(encodeEnvelope(drop))).toEqual(drop);
    expect(decodeEnvelope(utf8(JSON.stringify({ ...drop, purpose: null, storage: null })))).toEqual({ ...drop, purpose: undefined, storage: undefined });
    expect(decodeEnvelope(utf8(JSON.stringify({ ...reveal, purpose: "" })))).toEqual(reveal);
  });

  it("takes the last value of a duplicated key, as Go does", () => {
    const dup = '{"v":1,"type":"reveal","name":"first","name":"second","format":"text","secret":"s"}';
    expect(decodeEnvelope(utf8(dup)).name).toBe("second");
  });

  it("replaces invalid UTF-8 with U+FFFD, as Go does", () => {
    const bytes = new Uint8Array([...utf8('{"v":1,"type":"reveal","name":"n","format":"text","secret":"a'), 0xff, ...utf8('b"}')]);
    expect(decodeEnvelope(bytes).secret).toBe("a�b");
  });

  it("rejects malformed and unexpected documents", () => {
    const cases: [string, string][] = [
      ["not json", "nope"],
      ["empty", ""],
      ["array", "[]"],
      ["null", "null"],
      ["string", '"x"'],
      ["trailing data", JSON.stringify(reveal) + " {}"],
      ["trailing garbage", JSON.stringify(reveal) + "x"],
      ["unknown field", JSON.stringify({ ...reveal, extra: 1 })],
      ["version as string", JSON.stringify({ ...reveal, v: "1" })],
      ["version as float", JSON.stringify({ ...reveal, v: 1.5 })],
      ["version missing", JSON.stringify({ ...reveal, v: undefined })],
      ["name as number", JSON.stringify({ ...reveal, name: 5 })],
      ["secret as object", JSON.stringify({ ...reveal, secret: {} })],
      ["name null", JSON.stringify({ ...reveal, name: null })],
      ["reveal with drop fields", JSON.stringify({ ...reveal, retention: "session" })],
    ];
    for (const [name, doc] of cases) {
      expect(() => decodeEnvelope(utf8(doc)), name).toThrow(EnvelopeError);
    }
  });
});

describe("secret fields", () => {
  it("chooses text for printable UTF-8 and base64 otherwise", () => {
    expect(secretField(utf8("plain\ttext\nwith\r\nlines"))).toEqual({ format: "text", secret: "plain\ttext\nwith\r\nlines" });
    expect(secretField(utf8("é\u{1F511}"))).toEqual({ format: "text", secret: "é\u{1F511}" });
    expect(secretField(new Uint8Array([0, 1, 2, 3, 0xff]))).toEqual({ format: "base64", secret: "AAECA_8" });
    expect(secretField(new Uint8Array([0x61, 0xff, 0x62]))).toEqual({ format: "base64", secret: "Yf9i" });
    expect(secretField(new Uint8Array(0))).toEqual({ format: "text", secret: "" });
  });

  it("returns the raw bytes for both formats", () => {
    expect(text(secretBytes(reveal))).toBe("postgres://example");
    expect(bytesEqual(secretBytes({ ...reveal, format: "base64", secret: "AAECA_r7_P3-_w" }), new Uint8Array([0, 1, 2, 3, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]))).toBe(true);
  });
});

describe("revealAad and runeCount", () => {
  it("builds the domain separated display string", () => {
    expect(text(revealAad("staging-db-url", true))).toBe("burndrop/reveal/v1\nstaging-db-url\n1");
    expect(text(revealAad("staging-db-url", false))).toBe("burndrop/reveal/v1\nstaging-db-url\n0");
  });

  it("counts code points", () => {
    expect(runeCount("")).toBe(0);
    expect(runeCount("abc")).toBe(3);
    expect(runeCount("é\u{1F511}")).toBe(2);
  });
});
