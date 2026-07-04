const fs = require("fs");

const file = process.argv[2];
if (!file) {
  console.error("usage: node tools/luac51_probe.js <chunk.luac>");
  process.exit(2);
}

const buf = fs.readFileSync(file);
let p = 0;
let endian = "le";
let intSize = 4;
let sizeTSize = 8;
let instructionSize = 4;
let numberSize = 8;

function need(n, what) {
  if (p + n > buf.length) {
    throw new Error(`EOF while reading ${what} at 0x${p.toString(16)} need ${n}`);
  }
}

function u8(what = "u8") {
  need(1, what);
  return buf[p++];
}

function readUInt(n, what) {
  need(n, what);
  let v = 0n;
  if (endian === "le") {
    for (let i = 0; i < n; i++) v |= BigInt(buf[p + i]) << BigInt(8 * i);
  } else {
    for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(buf[p + i]);
  }
  p += n;
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${what} too large ${v} at 0x${(p - n).toString(16)}`);
  }
  return Number(v);
}

function bytes(n, what) {
  need(n, what);
  const out = buf.subarray(p, p + n);
  p += n;
  return out;
}

function luaString(what) {
  const start = p;
  const size = readUInt(sizeTSize, `${what}.size`);
  if (size === 0) return null;
  if (size > buf.length - p) {
    throw new Error(`${what} string size ${size} too large at 0x${start.toString(16)} remaining ${buf.length - p}`);
  }
  const s = bytes(size, what);
  return s.subarray(0, Math.max(0, s.length - 1)).toString("latin1");
}

function parseFunction(depth) {
  const start = p;
  const indent = "  ".repeat(depth);
  const source = luaString("source");
  const lineDefined = readUInt(intSize, "lineDefined");
  const lastLineDefined = readUInt(intSize, "lastLineDefined");
  const nups = u8("nups");
  const numparams = u8("numparams");
  const isVararg = u8("isVararg");
  const maxstack = u8("maxstack");
  const codeStart = p;
  const codeCount = readUInt(intSize, "codeCount");
  if (codeCount < 0 || codeCount > 1000000) {
    throw new Error(`bad codeCount ${codeCount} at 0x${codeStart.toString(16)}`);
  }
  bytes(codeCount * instructionSize, "code");
  const constCountOffset = p;
  const constCount = readUInt(intSize, "constCount");
  console.log(`${indent}func @0x${start.toString(16)} code=${codeCount} consts=${constCount} constCount@0x${constCountOffset.toString(16)} source=${JSON.stringify(source)} lines=${lineDefined}-${lastLineDefined}`);
  if (constCount < 0 || constCount > 1000000) {
    throw new Error(`bad constCount ${constCount} at 0x${constCountOffset.toString(16)}`);
  }
  for (let i = 0; i < constCount; i++) {
    const tOffset = p;
    const t = u8(`const[${i}].type`);
    if (t === 0) {
      // nil
    } else if (t === 1) {
      u8(`const[${i}].bool`);
    } else if (t === 3) {
      bytes(numberSize, `const[${i}].number`);
    } else if (t === 4) {
      luaString(`const[${i}].string`);
    } else {
      const around = buf.subarray(Math.max(0, tOffset - 16), Math.min(buf.length, tOffset + 32));
      throw new Error(`bad const type ${t} at const[${i}] offset 0x${tOffset.toString(16)} around ${around.toString("hex")}`);
    }
  }
  const protoCountOffset = p;
  const protoCount = readUInt(intSize, "protoCount");
  console.log(`${indent}  protos=${protoCount} protoCount@0x${protoCountOffset.toString(16)}`);
  if (protoCount < 0 || protoCount > 100000) {
    throw new Error(`bad protoCount ${protoCount} at 0x${protoCountOffset.toString(16)}`);
  }
  for (let i = 0; i < protoCount; i++) parseFunction(depth + 1);
  const lineInfoCount = readUInt(intSize, "lineInfoCount");
  bytes(lineInfoCount * intSize, "lineInfo");
  const localCount = readUInt(intSize, "localCount");
  for (let i = 0; i < localCount; i++) {
    luaString(`local[${i}].name`);
    readUInt(intSize, `local[${i}].startpc`);
    readUInt(intSize, `local[${i}].endpc`);
  }
  const upvalueCount = readUInt(intSize, "upvalueCount");
  for (let i = 0; i < upvalueCount; i++) luaString(`upvalue[${i}]`);
}

try {
  if (buf.length < 12 || buf[0] !== 0x1b || buf[1] !== 0x4c || buf[2] !== 0x75 || buf[3] !== 0x61) {
    throw new Error("not a Lua chunk");
  }
  p = 4;
  const version = u8("version");
  const format = u8("format");
  endian = u8("endianness") === 1 ? "le" : "be";
  intSize = u8("intSize");
  sizeTSize = u8("sizeTSize");
  instructionSize = u8("instructionSize");
  numberSize = u8("numberSize");
  const integral = u8("integralFlag");
  console.log(`header version=0x${version.toString(16)} format=${format} endian=${endian} int=${intSize} size_t=${sizeTSize} ins=${instructionSize} num=${numberSize} integral=${integral}`);
  parseFunction(0);
  console.log(`ok end=0x${p.toString(16)} length=0x${buf.length.toString(16)} trailing=${buf.length - p}`);
} catch (err) {
  console.error(`FAIL at 0x${p.toString(16)}: ${err.message}`);
  process.exit(1);
}
