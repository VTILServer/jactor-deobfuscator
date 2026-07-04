const fs = require("fs");
const cp1252 = new Map([
  [0x20ac, 0x80], [0x201a, 0x82], [0x0192, 0x83], [0x201e, 0x84],
  [0x2026, 0x85], [0x2020, 0x86], [0x2021, 0x87], [0x02c6, 0x88],
  [0x2030, 0x89], [0x0160, 0x8a], [0x2039, 0x8b], [0x0152, 0x8c],
  [0x017d, 0x8e], [0x2018, 0x91], [0x2019, 0x92], [0x201c, 0x93],
  [0x201d, 0x94], [0x2022, 0x95], [0x2013, 0x96], [0x2014, 0x97],
  [0x02dc, 0x98], [0x2122, 0x99], [0x0161, 0x9a], [0x203a, 0x9b],
  [0x0153, 0x9c], [0x017e, 0x9e], [0x0178, 0x9f],
]);

const input = process.argv[2] || "mau3-compiled.luac";
const output = process.argv[3] || input.replace(/\.luac$/i, ".repaired.luac");
const src = fs.readFileSync(input);

function decodeUtf8CharBytes(buffer) {
  const bytes = [];
  const unknown = [];
  for (let i = 0; i < buffer.length;) {
    const b = buffer[i];
    let cp;
    let len;
    if (b < 0x80) {
      cp = b; len = 1;
    } else if ((b & 0xe0) === 0xc0 && i + 1 < buffer.length) {
      cp = ((b & 0x1f) << 6) | (buffer[i + 1] & 0x3f); len = 2;
    } else if ((b & 0xf0) === 0xe0 && i + 2 < buffer.length) {
      cp = ((b & 0x0f) << 12) | ((buffer[i + 1] & 0x3f) << 6) | (buffer[i + 2] & 0x3f); len = 3;
    } else if ((b & 0xf8) === 0xf0 && i + 3 < buffer.length) {
      cp = ((b & 0x07) << 18) | ((buffer[i + 1] & 0x3f) << 12) | ((buffer[i + 2] & 0x3f) << 6) | (buffer[i + 3] & 0x3f); len = 4;
    } else {
      cp = 0xfffd; len = 1;
    }

    if (cp === 0xfffd) {
      bytes.push(0xfd);
      unknown.push(true);
    } else if (cp <= 0xff) {
      bytes.push(cp);
      unknown.push(false);
    } else if (cp1252.has(cp)) {
      bytes.push(cp1252.get(cp));
      unknown.push(false);
    } else {
      bytes.push(cp & 0xff);
      unknown.push(false);
    }
    i += len;
  }
  return { buf: Buffer.from(bytes), unknown };
}

const { buf, unknown } = decodeUtf8CharBytes(src);

function cloneAssign(assign) {
  return new Map(assign);
}

function byteAt(pos, assign) {
  return assign.has(pos) ? assign.get(pos) : buf[pos];
}

function setByte(pos, value, assign) {
  if (!unknown[pos]) return byteAt(pos, assign) === value;
  if (assign.has(pos)) return assign.get(pos) === value;
  assign.set(pos, value);
  return true;
}

function readFixedUInt(pos, n, assign) {
  let value = 0;
  for (let i = 0; i < n; i++) value += byteAt(pos + i, assign) * 2 ** (8 * i);
  return value;
}

function uintCandidates(pos, n, assign, max, preferred = []) {
  const fixed = [];
  const slots = [];
  for (let i = 0; i < n; i++) {
    const p = pos + i;
    if (unknown[p] && !assign.has(p)) slots.push(i);
    else fixed[i] = byteAt(p, assign);
  }
  if (slots.length === 0) {
    const value = readFixedUInt(pos, n, assign);
    return value <= max ? [value] : [];
  }
  const matches = [];
  const seen = new Set();
  function add(v) {
    if (v < 0 || v > max || seen.has(v)) return;
    for (let i = 0; i < n; i++) {
      if (fixed[i] !== undefined && ((v >> (8 * i)) & 0xff) !== fixed[i]) return;
    }
    seen.add(v);
    matches.push(v);
  }
  for (const v of preferred) add(v);
  const limit = Math.min(max, 200000);
  for (let v = 0; v <= limit; v++) add(v);
  return matches;
}

function assignUInt(pos, n, value, assign) {
  for (let i = 0; i < n; i++) {
    if (!setByte(pos + i, (value >> (8 * i)) & 0xff, assign)) return false;
  }
  return true;
}

function validTypeCandidates(pos, assign) {
  if (!unknown[pos] || assign.has(pos)) {
    const t = byteAt(pos, assign);
    return [0, 1, 3, 4].includes(t) ? [t] : [];
  }
  return [4, 3, 0, 1];
}

function stringCandidates(pos, sizeTSize, assign) {
  const max = Math.min(buf.length - pos - sizeTSize, 50000);
  const preferred = [];
  const known = readFixedUInt(pos, sizeTSize, assign);
  if (known <= max) preferred.push(known);
  return uintCandidates(pos, sizeTSize, assign, max, preferred).filter((size) => {
    if (size === 0) return true;
    const nulPos = pos + sizeTSize + size - 1;
    return nulPos < buf.length && (unknown[nulPos] || byteAt(nulPos, assign) === 0);
  });
}

let intSize = 4;
let sizeTSize = 8;
let instructionSize = 4;
let numberSize = 8;
const memo = new Set();

function parseString(pos, assign) {
  for (const size of stringCandidates(pos, sizeTSize, assign)) {
    const nextAssign = cloneAssign(assign);
    if (!assignUInt(pos, sizeTSize, size, nextAssign)) continue;
    if (size > 0 && !setByte(pos + sizeTSize + size - 1, 0, nextAssign)) continue;
    return { pos: pos + sizeTSize + size, assign: nextAssign };
  }
  return null;
}

function parseFunction(pos, assign, depth) {
  const key = `${pos}:${depth}:${assign.size}`;
  if (memo.has(key)) return null;
  const source = parseString(pos, assign);
  if (!source) return memo.add(key), null;
  pos = source.pos;
  assign = source.assign;
  if (pos + intSize * 2 + 4 > buf.length) return memo.add(key), null;
  pos += intSize * 2 + 4;

  const codePos = pos;
  const preferredCode = depth === 0 ? [742, 743, 765, 575] : [];
  for (const codeCount of uintCandidates(codePos, intSize, assign, 200000, preferredCode)) {
    let aCode = cloneAssign(assign);
    if (!assignUInt(codePos, intSize, codeCount, aCode)) continue;
    let p = codePos + intSize + codeCount * instructionSize;
    if (p + intSize > buf.length) continue;
    const constPreferred = [];
    const rawConst = readFixedUInt(p, intSize, aCode);
    if (rawConst <= 10000) constPreferred.push(rawConst);
    for (const constCount of uintCandidates(p, intSize, aCode, 10000, constPreferred)) {
      let a = cloneAssign(aCode);
      if (!assignUInt(p, intSize, constCount, a)) continue;
      let q = p + intSize;
      let ok = true;
      for (let i = 0; i < constCount && ok; i++) {
        if (q >= buf.length) { ok = false; break; }
        let matched = false;
        for (const t of validTypeCandidates(q, a)) {
          const ta = cloneAssign(a);
          if (!setByte(q, t, ta)) continue;
          let r = q + 1;
          if (t === 1) {
            if (r >= buf.length) continue;
            if (unknown[r] && !ta.has(r)) ta.set(r, byteAt(r, ta) ? 1 : 0);
            r += 1;
          } else if (t === 3) {
            r += numberSize;
          } else if (t === 4) {
            const parsed = parseString(r, ta);
            if (!parsed) continue;
            r = parsed.pos;
            a = parsed.assign;
            matched = true;
            q = r;
            break;
          }
          if (r <= buf.length) {
            a = ta; matched = true; q = r; break;
          }
        }
        if (!matched) ok = false;
      }
      if (!ok || q + intSize > buf.length) continue;
      for (const protoCount of uintCandidates(q, intSize, a, 10000, [readFixedUInt(q, intSize, a)])) {
        let ap = cloneAssign(a);
        if (!assignUInt(q, intSize, protoCount, ap)) continue;
        let r = q + intSize;
        let protoOk = true;
        for (let i = 0; i < protoCount && protoOk; i++) {
          const child = parseFunction(r, ap, depth + 1);
          if (!child) protoOk = false;
          else { r = child.pos; ap = child.assign; }
        }
        if (!protoOk || r + intSize > buf.length) continue;
        const lineCandidates = uintCandidates(r, intSize, ap, 200000, [readFixedUInt(r, intSize, ap), codeCount]);
        for (const lineInfoCount of lineCandidates) {
          let al = cloneAssign(ap);
          if (!assignUInt(r, intSize, lineInfoCount, al)) continue;
          let s = r + intSize + lineInfoCount * intSize;
          if (s + intSize > buf.length) continue;
          for (const localCount of uintCandidates(s, intSize, al, 10000, [readFixedUInt(s, intSize, al)])) {
            let au = cloneAssign(al);
            if (!assignUInt(s, intSize, localCount, au)) continue;
            let tpos = s + intSize;
            let localsOk = true;
            for (let i = 0; i < localCount && localsOk; i++) {
              const localName = parseString(tpos, au);
              if (!localName) { localsOk = false; break; }
              tpos = localName.pos + intSize * 2;
              au = localName.assign;
            }
            if (!localsOk || tpos + intSize > buf.length) continue;
            for (const upvalueCount of uintCandidates(tpos, intSize, au, 10000, [readFixedUInt(tpos, intSize, au)])) {
              let av = cloneAssign(au);
              if (!assignUInt(tpos, intSize, upvalueCount, av)) continue;
              let end = tpos + intSize;
              let upsOk = true;
              for (let i = 0; i < upvalueCount && upsOk; i++) {
                const up = parseString(end, av);
                if (!up) upsOk = false;
                else { end = up.pos; av = up.assign; }
              }
              if (upsOk) return { pos: end, assign: av };
            }
          }
        }
      }
    }
  }
  memo.add(key);
  return null;
}

if (buf[0] !== 0x1b || buf[1] !== 0x4c || buf[2] !== 0x75 || buf[3] !== 0x61) {
  throw new Error("decoded file is not a Lua chunk");
}
intSize = buf[7];
sizeTSize = buf[8];
instructionSize = buf[9];
numberSize = buf[10];

const result = parseFunction(12, new Map(), 0);
if (!result || result.pos !== buf.length) {
  throw new Error(`could not structurally repair chunk; stopped at ${result ? "0x" + result.pos.toString(16) : "no parse"}`);
}

for (const [pos, value] of result.assign) buf[pos] = value;

// For unknown instruction bytes that landed in the opcode byte, keep the
// operand bits but coerce invalid Lua 5.1 opcodes into MOVE. This makes the
// damaged chunk parseable without touching structural fields above.
function walkAndPatchOpcodes(pos) {
  const parsedString = () => {
    const size = readUIntPlain(pos, sizeTSize);
    pos += sizeTSize + size;
  };
  const readUIntPlain = (at, n) => {
    let v = 0;
    for (let i = 0; i < n; i++) v += buf[at + i] * 2 ** (8 * i);
    return v;
  };
  parsedString();
  pos += intSize * 2 + 4;
  const codeCount = readUIntPlain(pos, intSize);
  pos += intSize;
  for (let i = 0; i < codeCount; i++) {
    const opPos = pos + i * instructionSize;
    if ((buf[opPos] & 0x3f) > 37) buf[opPos] = buf[opPos] & 0xc0;
  }
  pos += codeCount * instructionSize;
  const constCount = readUIntPlain(pos, intSize);
  pos += intSize;
  for (let i = 0; i < constCount; i++) {
    const t = buf[pos++];
    if (t === 1) pos++;
    else if (t === 3) pos += numberSize;
    else if (t === 4) parsedString();
  }
  const protoCount = readUIntPlain(pos, intSize);
  pos += intSize;
  for (let i = 0; i < protoCount; i++) pos = walkAndPatchOpcodes(pos);
  const lineInfoCount = readUIntPlain(pos, intSize);
  pos += intSize + lineInfoCount * intSize;
  const localCount = readUIntPlain(pos, intSize);
  pos += intSize;
  for (let i = 0; i < localCount; i++) {
    parsedString();
    pos += intSize * 2;
  }
  const upvalueCount = readUIntPlain(pos, intSize);
  pos += intSize;
  for (let i = 0; i < upvalueCount; i++) parsedString();
  return pos;
}

walkAndPatchOpcodes(12);
fs.writeFileSync(output, buf);
console.log(`wrote ${output} (${buf.length} bytes, patched ${result.assign.size} structural bytes)`);
