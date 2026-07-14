# -*- coding: utf-8 -*-
"""
devirtualize.py  --  full deobfuscator for the jactor/luau VM obfuscator family.

Pipeline:  obfuscated .lua  ->  devirtualize (recover Lua 5.1 opcodes)
                            ->  pseudo listing (.pseudo.lua, human readable)
                            ->  Lua 5.1 bytecode (.luac)
                            ->  unluac  ->  runnable Lua (.lua)

Handles both VM variants:
  * runtime-RK   (opcode decodes constant-vs-register from a flag field; ~38 ops)
  * specialized  (constant-vs-register baked into distinct opcodes; ~75 ops)

Everything (opcode numbers, field slots, prototype layout, delimiters, VM
variable roles) is re-derived from each sample's own interpreter, so per-sample
opcode/field shuffling is handled automatically.
"""
import re, sys, os, subprocess, struct

# ============================================================ string codecs
_ALPHA = {}
_c = 0
for _i in range(32, 128):
    if _i not in (34, 92):
        _ALPHA[chr(_i)] = _c
        _ALPHA[_c] = chr(_i)
        _c += 1
_ALPHA_N = _c
_ESC = {}
_tbl = {32: 34, 33: 92, 34: 127}
for _i in range(1, 35):
    code = _tbl.get(_i, _i)
    _ESC[chr(code)] = chr(code + 31)
    _ESC[chr(code + 31)] = chr(code)

def base93num(v):
    out = 0
    for i in range(1, len(v) + 1):
        out += 93 ** (i - 1) * _ALPHA[v[-i]]
    return out

def _unescape(s):
    return re.sub('\x7f(.)', lambda m: _ESC[m.group(1)], s)

def decompress(text):
    d = dict(_ALPHA); idx = _ALPHA_N
    mm = re.match(r'(.*?)\|(.*)$', text, re.S)
    spans, content = mm.group(1), mm.group(2)
    groups = {}; pos = 0; width = 0
    for span in re.findall(r'\d+', spans):
        span = int(span); width += 1
        groups[width] = content[pos:pos + span * width]; pos += span * width
    out = []; prev = None
    for w in range(1, width + 1):
        g = groups[w]
        for k in range(0, len(g), w):
            tok = g[k:k + w]
            cur = d.get(base93num(tok))
            if prev is not None:
                if cur is not None:
                    out.append(cur); d[idx] = prev + cur[0]; idx += 1
                else:
                    cur = prev + prev[0]; out.append(cur); d[idx] = cur; idx += 1
            else:
                out.append(cur)
            prev = cur
    return _unescape(''.join(out))

def hexpairs(s):
    return re.sub(r'..', lambda m: chr((ord(m.group(0)[0]) - 65) * 16 + ord(m.group(0)[1]) - 66), s)

# ============================================================ lua text helpers
def read_lua_string(s, q):
    quote = s[q]; j = q + 1; buf = []
    while j < len(s):
        c = s[j]
        if c == quote:
            return ''.join(buf), j
        if c == '\\':
            nx = s[j + 1]
            if nx.isdigit():
                dd = re.match(r'\d{1,3}', s[j + 1:]).group(0)
                buf.append(chr(int(dd))); j += 1 + len(dd); continue
            buf.append({'n':'\n','r':'\r','t':'\t','a':'\a','b':'\b','f':'\f','v':'\v'}.get(nx, nx))
            j += 2; continue
        buf.append(c); j += 1
    raise ValueError('unterminated string')

def find_matching(s, start, o, c):
    depth = 0; quote = None; i = start
    while i < len(s):
        ch = s[i]
        if quote:
            if ch == '\\': i += 2; continue
            if ch == quote: quote = None
            i += 1; continue
        if ch in '"\'': quote = ch
        elif ch == o: depth += 1
        elif ch == c:
            depth -= 1
            if depth == 0: return i
        i += 1
    raise ValueError('unmatched ' + o)

def lnum(lit):
    """parse a luau numeric literal (0x/0b/decimal, with _ separators)."""
    s = lit.replace('_', '')
    neg = s.startswith('-')
    if neg: s = s[1:]
    if s[:2] in ('0x', '0X'): v = int(s, 16)
    elif s[:2] in ('0b', '0B'): v = int(s, 2)
    elif re.search(r'[.eE]', s): v = float(s)
    else: v = int(s)
    return -v if neg else v

NUMRE = r'[0-9][0-9a-fA-FxXbB_]*'

# ============================================================ blob + entry proto
def extract_blob(s):
    best = ''
    for m in re.finditer(r'[\w]+\(\s*"', s):
        q = s.find('"', m.start())
        try:
            payload, _ = read_lua_string(s, q)
            dec = hexpairs(decompress(payload))
            if len(dec) > len(best): best = dec
        except Exception:
            pass
    return best

def extract_entry_expr(s):
    best = None; pos = 0
    while True:
        m = re.search(r'return\s+[\w]+\s*\(', s[pos:])
        if not m: break
        brace = s.find('{', pos + m.end())
        if brace >= 0:
            try:
                be = find_matching(s, brace, '{', '}')
                suffix = s[be + 1:be + 90]
                if re.match(r'\s*,\s*[\w]+\s*\(\s*\)\s*\)\s*\(\s*\)', suffix) or re.match(r'\s*\)\s*\(\s*\)', suffix):
                    best = s[brace:be + 1]
            except Exception:
                pass
        pos = pos + m.end()
    assert best, 'entry proto not found'
    return best

# ------- restricted lua table-literal evaluator (entry proto tree) ----------
class Proto:
    __slots__ = ('arr', 'hash')
    def __init__(self): self.arr = []; self.hash = {}

class LuaLit:
    def __init__(self, s, blob): self.s = s; self.i = 0; self.n = len(s); self.blob = blob
    def ws(self):
        while self.i < self.n and self.s[self.i] in ' \t\r\n': self.i += 1
    def parse(self): self.ws(); return self.value()
    def value(self):
        self.ws(); c = self.s[self.i]
        if c == '{': return self.table()
        if c in '"\'':
            v, e = read_lua_string(self.s, self.i); self.i = e + 1; return v
        m = re.match(r'[A-Za-z_]\w*', self.s[self.i:])
        if m:
            name = m.group(0); self.i += len(name); self.ws()
            if self.i < self.n and self.s[self.i] == '(':
                args = self.arglist()
                if len(args) < 2: return None      # getfenv() / env
                a = int(args[0]); b = int(args[1]); return self.blob[a - 1:b]
            if name == 'true': return True
            if name == 'false': return False
            if name == 'nil': return None
            return name
        m = re.match(r'-?\s*0[xX][0-9a-fA-F_]+|-?\s*0[bB][01_]+|-?\s*[0-9][0-9_]*\.?[0-9_]*([eE][-+]?[0-9]+)?|-?\s*\.[0-9]+([eE][-+]?[0-9]+)?', self.s[self.i:])
        assert m, 'bad literal at %r' % self.s[self.i:self.i + 20]
        lit = m.group(0); self.i += len(lit); return lnum(lit)
    def arglist(self):
        self.i += 1; args = []; self.ws()
        if self.s[self.i] == ')': self.i += 1; return args
        while True:
            args.append(self.value()); self.ws(); c = self.s[self.i]
            if c == ',': self.i += 1; continue
            if c == ')': self.i += 1; break
            raise ValueError('bad arglist')
        return args
    def table(self):
        self.i += 1; p = Proto(); self.ws()
        if self.s[self.i] == '}': self.i += 1; return p
        while True:
            self.ws()
            m = re.match(r'([A-Za-z_]\w*)\s*=(?!=)', self.s[self.i:])
            if m:
                key = m.group(1); self.i += len(m.group(0)); p.hash[key] = self.value()
            else:
                p.arr.append(self.value())
            self.ws(); c = self.s[self.i]
            if c in ',;':
                self.i += 1; self.ws()
                if self.s[self.i] == '}': self.i += 1; break
                continue
            if c == '}': self.i += 1; break
            raise ValueError('bad table near %r' % self.s[self.i:self.i + 30])
        return p

# ============================================================ VM analysis
KW = set('if then elseif else end for while do function repeat until return local and or not nil true false in continue'.split())
def tokenize(s):
    toks = []; i = 0; n = len(s)
    while i < n:
        c = s[i]
        if c.isspace(): i += 1; continue
        if c.isalpha() or c == '_':
            j = i
            while j < n and (s[j].isalnum() or s[j] == '_'): j += 1
            w = s[i:j]; toks.append(('kw' if w in KW else 'name', w, i)); i = j; continue
        if c.isdigit() or (c == '.' and i + 1 < n and s[i + 1].isdigit()):
            j = i
            while j < n and (s[j].isalnum() or s[j] in '._'): j += 1
            toks.append(('num', s[i:j], i)); i = j; continue
        if c in '"\'':
            q = c; j = i + 1
            while j < n:
                if s[j] == '\\': j += 2
                elif s[j] == q: j += 1; break
                else: j += 1
            toks.append(('str', s[i:j], i)); i = j; continue
        two = s[i:i + 2]
        if two in ('==', '~=', '<=', '>=', '..', '+='):
            toks.append(('sym', two, i)); i += 2; continue
        toks.append(('sym', c, i)); i += 1
    toks.append(('eof', '', n)); return toks

class VM:
    pass

def analyse_vm(s):
    vm = VM()
    m = re.search(r'while true do local (\w+)=(\w+)\[(\w+)\]local (\w+)=(\1)\[(' + NUMRE + r')\]', s)
    assert m, 'interpreter loop not found'
    vm.INS, vm.CODE, vm.PC, vm.OP = m.group(1), m.group(2), m.group(3), m.group(4)
    vm.opfield = lnum(m.group(6))
    # interpreter function + prologue roles
    lf = list(re.finditer(r'local function (\w+)\((\w+)\)', s[:m.start()]))[-1]
    vm.fname, vm.farg = lf.group(1), lf.group(2)
    prologue = s[lf.end():m.start()]
    roles = {}
    for mm in re.finditer(r'local (\w+)=' + re.escape(vm.farg) + r'\[(' + NUMRE + r')\]', prologue):
        roles.setdefault(lnum(mm.group(2)), mm.group(1))
    vm.arg_roles = roles
    vm.CODEv = roles.get(2)              # instruction array  (i[2])
    vm.GLOBv = roles.get(4)              # globals/env        (i[4])
    vm.UPVv  = roles.get(5)              # upvalue array      (i[5])
    vm.REGv  = roles.get(6)              # register file      (i[6])
    # varargs: local d=b[1] local b=b[2]  where b=i[1]
    va = re.search(re.escape(roles.get(1, '\0')) + r'\[1\]local (\w+)=' + re.escape(roles.get(1, '\0')) + r'\[2\]', prologue) if roles.get(1) else None
    mva = re.search(r'local (\w+)=' + re.escape(roles.get(1, '')) + r'\[1\]local (\w+)=' + re.escape(roles.get(1, '')) + r'\[2\]', prologue) if roles.get(1) else None
    vm.VARARGv = mva.group(1) if mva else None
    vm.NARGv = mva.group(2) if mva else None
    # helpers
    hm = re.search(r'local function (\w+)\(\.\.\.\)return \w+\(\s*[\'"]#[\'"]', s)
    vm.CALLH = hm.group(1) if hm else None            # w(...) -> select('#',...),{...}
    um = re.search(r'local function (\w+)\((\w+),(\w+),(\w+)\)local \w+=\2\[\3\]', s)  # upvalue-cell builder e(b,c,_)
    vm.UPCELL = um.group(1) if um else None
    vm.SUBv = roles.get(3)                            # sub-prototype list (i[3])
    # loop top register (local <t> = -1 in the prologue)
    tm = re.search(r'local (\w+)=-1', prologue)
    vm.TOPv = tm.group(1) if tm else None
    # close-upvalues helper:  local function g(a,b) for _,_ in pairs(a) do if _[..]>=b then ...
    cm = re.search(r'local function (\w+)\((\w+),(\w+)\)for', s)
    vm.CLOSEH = cm.group(1) if cm else None
    # closure builder: the function that contains the split() decode of instructions
    bm = re.search(r'function (\w+)\(\w+,\w+,\w+,\w+\)local \w+ local \w+=\w+\[', s)
    vm.BUILDER = bm.group(1) if bm else None
    # dispatch tree
    ifpos = re.search(r'if\s+' + re.escape(vm.OP) + r'\s*[<>]|if\s+' + NUMRE + r'\s*[<>]\s*' + re.escape(vm.OP), s[m.end() - 1:])
    start = m.end() - 1 + ifpos.start()
    vm.leaves = parse_switch(s[start:], vm.OP)
    # CLOSURE pseudo-op codes: parse the CLOSURE handler for the follow-row opcodes
    vm.MOVECODE = vm.UPVCODE = vm.MOVEREG = vm.UPVIDX = None
    P = re.escape(vm.INS); U = re.escape(vm.UPVv); CODE = re.escape(vm.CODEv or '')
    for lo, hi, txt in vm.leaves:
        ns = re.sub(r'\s+', '', txt)
        cm2 = re.search(r'if(\w+)==(' + NUMRE + r')then\w+=' + re.escape(vm.UPCELL or '\0') + r'\(\w+,\w+\[(' + NUMRE + r')\],', ns)
        if cm2:
            vm.MOVECODE = lnum(cm2.group(2)); vm.MOVEREG = lnum(cm2.group(3))
        um2 = re.search(r'elseif\w+==(' + NUMRE + r')then\w+=' + U + r'\[\w+\[(' + NUMRE + r')\]\]', ns)
        if um2:
            vm.UPVCODE = lnum(um2.group(1)); vm.UPVIDX = lnum(um2.group(2))
    return vm

def parse_switch(s, opvar):
    toks = tokenize(s); leaves = []
    CMP = ('<', '>', '<=', '>=', '==', '~=')
    def cond_at(pos):
        a, b, c = toks[pos], toks[pos + 1], toks[pos + 2]
        if a[1] == opvar and b[1] in CMP and c[0] == 'num':
            return (True, b[1], int(c[1].replace('_', ''), 0), pos + 3)
        if a[0] == 'num' and b[1] in CMP and c[1] == opvar:
            return (False, b[1], int(a[1].replace('_', ''), 0), pos + 3)
        return None
    def is_switch(i):
        return i < len(toks) and toks[i][0] == 'kw' and toks[i][1] in ('if', 'elseif') and cond_at(i + 1) is not None
    def parse_leaf(i, lo, hi):
        depth = 0; pend = 0; j = i
        while True:
            t = toks[j]
            if t[0] == 'eof': raise Exception('eof in leaf')
            if depth == 0 and t[0] == 'kw' and t[1] in ('elseif', 'else', 'end'):
                leaves.append((lo, hi, s[toks[i][2]:toks[j][2]])); return j
            if t[0] == 'kw':
                v = t[1]
                if v in ('if', 'function'): depth += 1
                elif v in ('for', 'while'): depth += 1; pend += 1
                elif v == 'do':
                    if pend > 0: pend -= 1
                    else: depth += 1
                elif v == 'repeat': depth += 1
                elif v == 'until': depth -= 1
                elif v == 'end': depth -= 1
            j += 1
    def parse_switch_i(i, lo, hi):
        run_lo, run_hi = lo, hi; pos = i
        while True:
            cc = cond_at(pos + 1); assert cc, 'bad cond'
            left, op, C, after = cc
            if not left: op = {'<': '>', '>': '<', '<=': '>=', '>=': '<='}.get(op, op)
            assert toks[after][1] == 'then'
            t_lo, t_hi = run_lo, run_hi
            if op == '<': t_hi = min(t_hi, C - 1); run_lo = max(run_lo, C)
            elif op == '>': t_lo = max(t_lo, C + 1); run_hi = min(run_hi, C)
            elif op == '<=': t_hi = min(t_hi, C); run_lo = max(run_lo, C + 1)
            elif op == '>=': t_lo = max(t_lo, C); run_hi = min(run_hi, C - 1)
            elif op == '==': t_lo = t_hi = C
            body = after + 1
            stop = parse_switch_i(body, t_lo, t_hi) if is_switch(body) else parse_leaf(body, t_lo, t_hi)
            d = toks[stop]
            if d[1] == 'elseif': pos = stop
            elif d[1] == 'else':
                b2 = stop + 1
                stop2 = parse_switch_i(b2, run_lo, run_hi) if is_switch(b2) else parse_leaf(b2, run_lo, run_hi)
                return stop2 + 1
            elif d[1] == 'end': return stop + 1
            else: raise Exception('bad delim ' + str(d))
    parse_switch_i(0, 0, 10 ** 9)
    return leaves

# ============================================================ handler classifier
# Operand descriptors returned to the emitter:
#   ('reg', slot)                     always a register  (value = register index)
#   ('imm', slot)                     always a constant  (value -> constant pool)
#   ('rk', flagslot, kslot, regslot)  runtime RK: const if raw[flagslot] truthy else reg
def classify(vm):
    R = re.escape(vm.REGv); P = re.escape(vm.INS); G = re.escape(vm.GLOBv)
    U = re.escape(vm.UPVv); PC = re.escape(vm.PC)
    N = r'(' + NUMRE + r')'
    REG = R + r'\[' + P + r'\[' + N + r'\]\]'     # o[p[N]]  -> register
    IMM = P + r'\[' + N + r'\]'                    # p[N]     -> immediate/field
    def num(x): return lnum(x)

    def rk_blocks(ns):
        """parse the two runtime-RK if-blocks; return {var:('rk',flag,k,reg)} and remainder."""
        blocks = {}
        pat = r'if' + P + r'\[' + N + r'\]then(\w+)=' + P + r'\[' + N + r'\]else\2=' + REG + r'end'
        def repl(m):
            flag, var, k, reg = m.group(1), m.group(2), m.group(3), m.group(4)
            blocks[var] = ('rk', num(flag), num(k), num(reg)); return ''
        rem = re.sub(pat, repl, ns)
        return blocks, rem

    def operand_at(expr, blocks):
        """resolve a RHS operand token (a var from rk-blocks, or inline reg/imm)."""
        m = re.fullmatch(REG, expr)
        if m: return ('reg', num(m.group(1)))
        m = re.fullmatch(IMM, expr)
        if m: return ('imm', num(m.group(1)))
        if expr in blocks: return blocks[expr]
        return None

    def strip_decls(txt):
        """token-level removal of declaration-only locals (`local a,b` with no =),
        then rejoin without whitespace so the structural regexes apply."""
        toks = tokenize(txt); out = []; i = 0
        while i < len(toks):
            t = toks[i]
            if t[0] == 'kw' and t[1] == 'local':
                j = i + 1; names = 0
                while j < len(toks) and toks[j][0] == 'name':
                    names += 1; j += 1
                    if j < len(toks) and toks[j][1] == ',': j += 1; continue
                    break
                if names > 0 and (j >= len(toks) or toks[j][1] != '='):
                    i = j; continue
            out.append(t); i += 1
        return ''.join(tk[1] for tk in out)

    ARITH = {'+': 'ADD', '-': 'SUB', '*': 'MUL', '/': 'DIV', '%': 'MOD', '^': 'POW'}
    CMP = {'==': 'EQ', '<': 'LT', '<=': 'LE'}
    spec = {}
    warnings = []

    for lo, hi, txt in vm.leaves:
        ns = strip_decls(txt)
        name = None; info = {}
        if ns == '' or ns.strip() == '':
            spec[lo] = {'name': 'NOP'}; continue

        blocks, rem = rk_blocks(ns)

        def flag_slot(expr):
            expr = expr.strip('()')
            fm = re.fullmatch(IMM + r'~=0', expr) or re.fullmatch(IMM, expr)
            return num(fm.group(1)) if fm else None

        # ---- arithmetic:  o[p[A]] = X op Y  (both variants) -------------------
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=(.+?)([-+*/%^])(.+)', rem)
        if m and (m.group(3) in ARITH):
            A = num(m.group(1))
            lop = operand_at(m.group(2), blocks)
            rop = operand_at(m.group(4), blocks)
            if lop and rop:
                spec[lo] = {'name': ARITH[m.group(3)], 'A': A, 'B': lop, 'C': rop}; continue

        # ---- comparisons:  if(X op Y) ~= FLAG then <pc>+=1 --------------------
        m = re.fullmatch(r'if\((.+?)(==|<=|<)(.+?)\)~=(.+?)then' + PC + r'(\+=1|=' + PC + r'\+1)end', rem)
        if m and m.group(2) in CMP:
            lop = operand_at(m.group(1), blocks); rop = operand_at(m.group(3), blocks)
            fs = flag_slot(m.group(4))
            if lop and rop and fs is not None:
                spec[lo] = {'name': CMP[m.group(2)], 'A_flag': fs, 'B': lop, 'C': rop}; continue

        # ---- MOVE / LOADK / GETGLOBAL / unary / table reads ------------------
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=' + R + r'\[' + P + r'\[' + N + r'\]\]', rem)
        if m:
            spec[lo] = {'name': 'MOVE', 'A': num(m.group(1)), 'B': num(m.group(2))}; continue
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=' + P + r'\[' + N + r'\]', rem)
        if m:
            spec[lo] = {'name': 'LOADK', 'A': num(m.group(1)), 'K': num(m.group(2))}; continue
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=' + P + r'\[' + N + r'\](?:~=0)?if(.+?)then' + PC + r'(\+=1|=' + PC + r'\+1)end', rem)
        if m:
            fs = flag_slot(m.group(3))
            if fs is not None:
                spec[lo] = {'name': 'LOADBOOL', 'A': num(m.group(1)), 'B': num(m.group(2)), 'C': fs}; continue
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=' + G + r'\[' + P + r'\[' + N + r'\]\]', rem)
        if m:
            spec[lo] = {'name': 'GETGLOBAL', 'A': num(m.group(1)), 'K': num(m.group(2))}; continue
        m = re.fullmatch(G + r'\[' + P + r'\[' + N + r'\]\]=' + R + r'\[' + P + r'\[' + N + r'\]\]', rem)
        if m:
            spec[lo] = {'name': 'SETGLOBAL', 'K': num(m.group(1)), 'A': num(m.group(2))}; continue
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=not' + R + r'\[' + P + r'\[' + N + r'\]\]', rem)
        if m:
            spec[lo] = {'name': 'NOT', 'A': num(m.group(1)), 'B': num(m.group(2))}; continue
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=-' + R + r'\[' + P + r'\[' + N + r'\]\]', rem)
        if m:
            spec[lo] = {'name': 'UNM', 'A': num(m.group(1)), 'B': num(m.group(2))}; continue
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=#' + R + r'\[' + P + r'\[' + N + r'\]\]', rem)
        if m:
            spec[lo] = {'name': 'LEN', 'A': num(m.group(1)), 'B': num(m.group(2))}; continue
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=\{\}', rem)
        if m:
            spec[lo] = {'name': 'NEWTABLE', 'A': num(m.group(1))}; continue
        # GETTABLE: o[p[A]] = o[p[B]][ C ]  where C is reg or imm
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]=' + R + r'\[' + P + r'\[' + N + r'\]\]\[(.+)\]', rem)
        if m:
            C = operand_at(m.group(3), blocks)
            if C:
                spec[lo] = {'name': 'GETTABLE', 'A': num(m.group(1)), 'B': num(m.group(2)), 'C': C}; continue
        # SETTABLE: o[p[A]][ K ] = V
        m = re.fullmatch(R + r'\[' + P + r'\[' + N + r'\]\]\[(.+?)\]=(.+)', rem)
        if m:
            K = operand_at(m.group(2), blocks); V = operand_at(m.group(3), blocks)
            if K and V:
                spec[lo] = {'name': 'SETTABLE', 'A': num(m.group(1)), 'B': K, 'C': V}; continue

        # ---- LOADNIL:  for X=p[A],p[B] do o[X]=nil end -----------------------
        m = re.fullmatch(r'for(\w+)=' + P + r'\[' + N + r'\],' + P + r'\[' + N + r'\]do' + R + r'\[\1\]=nilend', rem)
        if m:
            spec[lo] = {'name': 'LOADNIL', 'A': num(m.group(2)), 'B': num(m.group(3))}; continue

        # ---- JMP:  <pc> += p[sBx]   or   <pc> = <pc> + p[sBx] ----------------
        m = re.fullmatch(PC + r'\+=' + P + r'\[' + N + r'\]', rem) or re.fullmatch(PC + r'=' + PC + r'\+' + P + r'\[' + N + r'\]', rem)
        if m:
            spec[lo] = {'name': 'JMP', 'sBx': num(m.group(1))}; continue

        # ---- CONCAT (compound):  local s=p[B] local acc=o[s] for x=s+1,p[C] do acc..=o[x] end o[p[A]]=acc
        m = re.fullmatch(r'local(\w+)=' + P + r'\[' + N + r'\]local(\w+)=' + R + r'\[\1\]for(\w+)=\1\+1,' + P + r'\[' + N + r'\]do\3\.\.=' + R + r'\[\4\]end' + R + r'\[' + P + r'\[' + N + r'\]\]=\3', rem)
        if m:
            spec[lo] = {'name': 'CONCAT', 'B': num(m.group(2)), 'C': num(m.group(5)), 'A': num(m.group(6))}; continue
        # ---- CONCAT (explicit):  local acc=o[p[B]] for x=p[B]+1,p[C] do acc=acc..o[x] end o[p[A]]=acc
        m = re.fullmatch(r'local(\w+)=' + R + r'\[' + P + r'\[' + N + r'\]\]for(\w+)=' + P + r'\[' + N + r'\]\+1,' + P + r'\[' + N + r'\]do\1=\1\.\.' + R + r'\[\2\]end' + R + r'\[' + P + r'\[' + N + r'\]\]=\1', rem)
        if m:
            spec[lo] = {'name': 'CONCAT', 'B': num(m.group(2)), 'C': num(m.group(5)), 'A': num(m.group(6))}; continue

        # ---- TEST / TESTSET --------------------------------------------------
        m = re.fullmatch(r'if\(not' + R + r'\[' + P + r'\[' + N + r'\]\]\)==(.+?)then' + PC + r'(\+=1|=' + PC + r'\+1)end', rem)
        if m:
            fs = flag_slot(m.group(2))
            if fs is not None:
                spec[lo] = {'name': 'TEST', 'A': num(m.group(1)), 'C': fs}; continue
        m = re.fullmatch(r'local(\w+)=' + P + r'\[' + N + r'\]if\(not' + R + r'\[\1\]\)==(.+?)then' + PC + r'(\+=1|=' + PC + r'\+1)else' + R + r'\[' + P + r'\[' + N + r'\]\]=' + R + r'\[\1\]end', rem)
        if m:
            fs = flag_slot(m.group(3))
            if fs is not None:
                spec[lo] = {'name': 'TESTSET', 'B': num(m.group(2)), 'C': fs, 'A': num(m.group(5))}; continue
        # sample29 TESTSET: local a=p[A] local b=p[B] if(not o[b])==(p[C]~=0) then pc+=1 else o[a]=o[b] end
        m = re.fullmatch(r'local(\w+)=' + P + r'\[' + N + r'\]local(\w+)=' + P + r'\[' + N + r'\]if\(not' + R + r'\[\3\]\)==(.+?)then' + PC + r'(\+=1|=' + PC + r'\+1)else' + R + r'\[\1\]=' + R + r'\[\3\]end', rem)
        if m:
            fs = flag_slot(m.group(5))
            if fs is not None:
                spec[lo] = {'name': 'TESTSET', 'A': num(m.group(2)), 'B': num(m.group(4)), 'C': fs}; continue

        # ---- SELF ------------------------------------------------------------
        # o[A+1]=o[B]; o[A]=o[B][K]
        m = re.fullmatch(r'local(\w+)=' + P + r'\[' + N + r'\]local(\w+)=' + P + r'\[' + N + r'\]' + R + r'\[\1\+1\]=' + R + r'\[\3\]' + R + r'\[\1\]=' + R + r'\[\3\]\[(.+)\]', rem)
        if m:
            C = operand_at(m.group(5), blocks)
            if C:
                spec[lo] = {'name': 'SELF', 'A': num(m.group(2)), 'B': num(m.group(4)), 'C': C}; continue
        # sample29 SELF: local b=p[9] local a=p[8] local c<rk> o[b+1]=o[a] o[b]=o[a][c]
        m = re.fullmatch(r'local(\w+)=' + P + r'\[' + N + r'\]local(\w+)=' + P + r'\[' + N + r'\]local(\w+)' + R + r'\[\1\+1\]=' + R + r'\[\3\]' + R + r'\[\1\]=' + R + r'\[\3\]\[\5\]', rem)
        if m:
            C = blocks.get(m.group(5))
            if C:
                spec[lo] = {'name': 'SELF', 'A': num(m.group(2)), 'B': num(m.group(4)), 'C': C}; continue

        # ---- GETUPVAL / SETUPVAL --------------------------------------------
        m = re.fullmatch(r'local(\w+)=' + U + r'\[' + P + r'\[' + N + r'\]\]' + R + r'\[' + P + r'\[' + N + r'\]\]=\1\[(' + NUMRE + r')\]\[\1\[(' + NUMRE + r')\]\]', rem)
        if m:
            spec[lo] = {'name': 'GETUPVAL', 'A': num(m.group(3)), 'B': num(m.group(2))}; continue
        m = re.fullmatch(r'local(\w+)=' + U + r'\[' + P + r'\[' + N + r'\]\]\1\[(' + NUMRE + r')\]\[\1\[(' + NUMRE + r')\]\]=' + R + r'\[' + P + r'\[' + N + r'\]\]', rem)
        if m:
            spec[lo] = {'name': 'SETUPVAL', 'A': num(m.group(5)), 'B': num(m.group(2))}; continue
        # sample29 upvalue cells use .store/.index
        m = re.fullmatch(r'local(\w+)=' + U + r'\[' + P + r'\[' + N + r'\]\]' + R + r'\[' + P + r'\[' + N + r'\]\]=\1\.store\[\1\.index\]', rem)
        if m:
            spec[lo] = {'name': 'GETUPVAL', 'A': num(m.group(3)), 'B': num(m.group(2))}; continue
        m = re.fullmatch(r'local(\w+)=' + U + r'\[' + P + r'\[' + N + r'\]\]\1\.store\[\1\.index\]=' + R + r'\[' + P + r'\[' + N + r'\]\]', rem)
        if m:
            spec[lo] = {'name': 'SETUPVAL', 'A': num(m.group(3)), 'B': num(m.group(2))}; continue

        # ================= special control-flow ops =======================
        CH = re.escape(vm.CALLH or '\0'); TOP = re.escape(vm.TOPv or '\0')
        VA = re.escape(vm.VARARGv or '\0'); NA = re.escape(vm.NARGv or '\0')
        CLOSEH = re.escape(vm.CLOSEH or '\0'); SUB = re.escape(vm.SUBv or '\0')
        BLD = re.escape(vm.BUILDER or '\0'); UNP = r'\w+'
        def slot_of_local(var, text):
            mm = re.search(r'local' + re.escape(var) + r'=' + P + r'\[' + N + r'\]', text)
            return num(mm.group(1)) if mm else None
        def argcount(base, expr):
            # descriptor for a CALL/TAILCALL argument count: ('top',) or ('fix', slot)
            if expr == vm.TOPv: return ('top',)
            mm = re.fullmatch(re.escape(base) + r'\+' + P + r'\[' + N + r'\]', expr)
            return ('fix', num(mm.group(1))) if mm else None

        # CLOSE:  closeh(k, p[A])
        m = re.fullmatch(CLOSEH + r'\(\w+,' + P + r'\[' + N + r'\]\)', ns)
        if m:
            spec[lo] = {'name': 'CLOSE', 'A': num(m.group(1))}; continue

        # RETURN none:  i=0 return 0,{}
        if re.fullmatch(PC + r'=0return0,\{\}', ns):
            spec[lo] = {'name': 'RETURN0'}; continue

        # TAILCALL: closeh(..) return CALLH(R[base](unpack(R,base+1, UP)))
        m = re.search(CLOSEH + r'\(\w+,\w+\)return' + CH + r'\(' + R + r'\[(\w+)\]\(' + UNP + r'\(' + R + r',\1\+1,(.+?)\)\)\)$', ns)
        if m:
            base = m.group(1); As = slot_of_local(base, ns)
            B = argcount(base, m.group(2))
            if As is not None and B is not None:
                spec[lo] = {'name': 'TAILCALL', 'A': As, 'B': B}; continue

        # CALL: CALLH(R[base](unpack(R,base+1, UP)))  then result copy
        m = re.search(CH + r'\(' + R + r'\[(\w+)\]\(' + UNP + r'\(' + R + r',\1\+1,(.+?)\)\)\)', ns)
        if m and 'return' + vm.CALLH not in ns:
            base = m.group(1); As = slot_of_local(base, ns)
            B = argcount(base, m.group(2))
            # results: TOP=base+..-1  -> multret (C=('multi',));  for ..=1,P[Ccnt] -> C=('fix',slot)
            C = None
            if re.search(re.escape(vm.TOPv or '\0') + r'=' + re.escape(base) + r'\+\w+-1', ns):
                C = ('multi',)
            else:
                cm = re.search(r'for\w+=1,' + P + r'\[' + N + r'\]do' + R + r'\[' + re.escape(base) + r'\+', ns)
                if cm: C = ('fix', num(cm.group(1)))
            if As is not None and B is not None and C is not None:
                spec[lo] = {'name': 'CALL', 'A': As, 'B': B, 'C': C}; continue

        # RETURN some:  local base=p[As] ... closeh(..) return cnt,tbl
        if re.search(CLOSEH + r'\(\w+,\w+\)return\w+,\w+$', ns):
            bm = re.match(r'local(\w+)=' + P + r'\[' + N + r'\]', ns)
            if bm:
                base = bm.group(1); As = num(bm.group(2))
                if re.search(re.escape(vm.TOPv or '\0') + r'-' + re.escape(base) + r'\+1', ns):
                    B = ('top',)
                else:
                    cm = re.search(r'local\w+=' + P + r'\[' + N + r'\]local\w+=\{\}', ns)
                    B = ('fix', num(cm.group(1))) if cm else None
                if B is not None:
                    spec[lo] = {'name': 'RETURN', 'A': As, 'B': B}; continue

        # VARARG:  local base=p[As]  [TOP=base+NARG]  for x=1,COUNT do R[base+x]=VARARG[x] end
        m = re.search(r'local(\w+)=' + P + r'\[' + N + r'\].*?for\w+=1,(.+?)do' + R + r'\[\1\+\w+\]=' + VA + r'\[\w+\]end', ns)
        if m:
            As = num(m.group(2)); cnt = m.group(3)
            if cnt == vm.NARGv:
                B = ('top',)
            else:
                cm = re.fullmatch(P + r'\[' + N + r'\]', cnt)
                B = ('fix', num(cm.group(1))) if cm else None
            if B is not None:
                spec[lo] = {'name': 'VARARG', 'A': As, 'B': B}; continue

        # FORPREP: local c=p[As] ... R[c]=<..>-b  R[c+1]=..  R[c+2]=..  pc += p[sBx]
        m = re.search(r'local(\w+)=' + P + r'\[' + N + r'\].*?' + R + r'\[\1\]=.+?-\w+' + R + r'\[\1\+1\]=\w+' + R + r'\[\1\+2\]=\w+' + PC + r'(?:\+=|=' + PC + r'\+)' + P + r'\[' + N + r'\]', ns)
        if m and '~=nil' not in ns and '..' not in ns:
            spec[lo] = {'name': 'FORPREP', 'A': num(m.group(2)), 'sBx': num(m.group(3))}; continue

        # FORLOOP: local a=p[As] local b=R[a+2] local d=R[a]+b ... if cond then R[a2]=d R[a2+3]=d pc+=p[sBx] end
        m = re.search(R + r'\[\w+\+2\]local\w+=' + R + r'\[\w+\]\+\w+.*?' + PC + r'(?:\+=|=' + PC + r'\+)' + P + r'\[' + N + r'\]', ns)
        if m:
            am = re.match(r'local(\w+)=' + P + r'\[' + N + r'\]', ns)
            if am:
                spec[lo] = {'name': 'FORLOOP', 'A': num(am.group(2)), 'sBx': num(m.group(1))}; continue

        # TFORLOOP: local d=p[As] ... {call} for x=1,P[Ccnt] do R[e+x-1]=.. end if R[e]~=nil ...
        m = re.search(r'local(\w+)=' + P + r'\[' + N + r'\]local\w+=' + R + r'\[\1\]local\w+=\1\+3.*?for\w+=1,' + P + r'\[' + N + r'\]do' + R + r'\[\w+\+\w+-1\]=', ns)
        if m and '~=nil' in ns:
            spec[lo] = {'name': 'TFORLOOP', 'A': num(m.group(2)), 'C': num(m.group(3))}; continue

        # SETLIST: local d=p[As] ... [(x)*50]  copies R[d+c] into R[d]
        if '*50' in ns:
            am = re.match(r'local(\w+)=' + P + r'\[' + N + r'\]', ns)
            # C block:  (P[N]-1)*50 -> Lua C = raw[N] ;   P[N]*50 -> Lua C = raw[N]+1
            cm1 = re.search(r'\(' + P + r'\[' + N + r'\]-1\)\*50', ns)
            cm2 = re.search(P + r'\[' + N + r'\]\*50', ns)
            if cm1: C = ('cval', num(cm1.group(1)))
            elif cm2: C = ('block', num(cm2.group(1)))
            else: C = ('cval', None)
            # B count: 'for c=1,TOP-d' -> top ; 'for c=1,P[N]' -> raw[N] (element count)
            bm = re.search(r'for\w+=1,' + P + r'\[' + N + r'\]do', ns)
            if re.search(r'for\w+=1,' + re.escape(vm.TOPv or '\0') + r'-', ns):
                B = ('top',)
            elif bm:
                B = ('cnt', num(bm.group(1)))
            else:
                B = ('top',)
            if am:
                spec[lo] = {'name': 'SETLIST', 'A': num(am.group(2)), 'B': B, 'C': C}; continue

        # CLOSURE: local d=SUB[p[proto]] local n=d[nups] if n==0 then R[p[A]]=BLD(..) else ...
        m = re.search(r'local(\w+)=' + SUB + r'\[' + P + r'\[' + N + r'\]\]local(\w+)=\1\[(' + NUMRE + r')\]', ns)
        if m and vm.BUILDER and (vm.BUILDER + '(') in ns:
            am = re.search(R + r'\[' + P + r'\[' + N + r'\]\]=' + re.escape(vm.BUILDER) + r'\(', ns)
            if am:
                spec[lo] = {'name': 'CLOSURE', 'A': num(am.group(1)), 'proto': num(m.group(2)), 'nups_slot': num(m.group(4))}; continue

        warnings.append((lo, ns))
        spec[lo] = {'name': '?', 'raw': ns}

    return spec, warnings


# ============================================================ delimiters + layout
def detect_delimiters(s):
    # method form  x:split("A")   or function form  f(x,"A")
    ms = re.findall(r':split\("(.)"\)', s)
    if len(ms) >= 3:
        return ms[0], ms[1], ms[2]
    al = re.search(r'local (\w+)=string\.split', s)
    if al:
        fn = re.escape(al.group(1))
        ms = re.findall(fn + r'\([^,]*,"(.)"\)', s)
        if len(ms) >= 3:
            return ms[0], ms[1], ms[2]
    raise ValueError('could not detect split delimiters')

def detect_layout(vm, s, d1):
    """derive proto-table slot numbers: code, constmap, subprotos, params, nups."""
    layout = {'code': 1, 'constmap': 2, 'nups': 3, 'subprotos': 4, 'params': 5}
    # code slot: split(decode(e[CODE]), d1)  either method or function form
    m = re.search(r'\(\s*\w+\(\w+\[(' + NUMRE + r')\]\)\s*,\s*"' + re.escape(d1) + r'"', s) \
        or re.search(r'\w+\(\w+\[(' + NUMRE + r')\]\)\s*:split\("' + re.escape(d1) + r'"', s)
    if m: layout['code'] = lnum(m.group(1))
    # constmap slot: 'do local X=e[N]' right after the split
    m = re.search(r'"' + re.escape(d1) + r'"\).{0,40}?do\s*local\s+\w+\s*=\s*\w+\[(' + NUMRE + r')\]', s, re.S)
    if m: layout['constmap'] = lnum(m.group(1))
    # subprotos slot: local h=e[N] just before 'if <isMain> then'
    m = re.search(r'local\s+(\w+)\s*=\s*(\w+)\[(' + NUMRE + r')\]\s*if\s+\w+\s+then', s)
    if m: layout['subprotos'] = lnum(m.group(3))
    # params slot: local j=e[N] return function
    m = re.search(r'local\s+\w+\s*=\s*\w+\[(' + NUMRE + r')\]\s*return\s+function', s)
    if m: layout['params'] = lnum(m.group(1))
    if vm.MOVECODE is not None:            # nups slot = the proto field CLOSURE reads
        mm = re.search(r'local\s+\w+\s*=\s*\w+\[(' + NUMRE + r')\]\s*if\s+\w+==0\s*then', s)
        if mm: layout['nups'] = lnum(mm.group(1))
    return layout

# ============================================================ instruction decode
class Node:
    pass

def decode_instructions(code_str, constmap, opfield, d1, d2, d3):
    cm = constmap.hash if isinstance(constmap, Proto) else constmap
    decoded = decompress(code_str)
    out = []
    for group in decoded.split(d1):
        if group == '':
            continue
        raw = {}
        for pair in group.split(d2):
            kv = pair.split(d3)
            if len(kv) >= 2 and kv[0] != '' and kv[0] in cm and kv[1] in cm:
                raw[cm[kv[0]]] = cm[kv[1]]
        out.append(raw)
    return out

def build_proto(pnode, vm, layout, d1, d2, d3):
    node = Node()
    arr = pnode.arr
    def slot(i):
        return arr[i - 1] if 1 <= i <= len(arr) else None
    def as_int(v):
        return int(v) if isinstance(v, (int, float)) else 0
    node.params = as_int(slot(layout['params']))
    node.nups = as_int(slot(layout['nups']))
    node.instructions = decode_instructions(slot(layout['code']), slot(layout['constmap']), vm.opfield, d1, d2, d3)
    subs = slot(layout['subprotos'])
    node.subprotos = []
    if isinstance(subs, Proto):
        for sp in subs.arr:
            if isinstance(sp, Proto):
                node.subprotos.append(build_proto(sp, vm, layout, d1, d2, d3))
    node.is_vararg = 0
    return node

# ============================================================ Lua 5.1 emitter
LUA_OP = {
    'MOVE': 0, 'LOADK': 1, 'LOADBOOL': 2, 'LOADNIL': 3, 'GETUPVAL': 4, 'GETGLOBAL': 5,
    'GETTABLE': 6, 'SETGLOBAL': 7, 'SETUPVAL': 8, 'SETTABLE': 9, 'NEWTABLE': 10, 'SELF': 11,
    'ADD': 12, 'SUB': 13, 'MUL': 14, 'DIV': 15, 'MOD': 16, 'POW': 17, 'UNM': 18, 'NOT': 19,
    'LEN': 20, 'CONCAT': 21, 'JMP': 22, 'EQ': 23, 'LT': 24, 'LE': 25, 'TEST': 26, 'TESTSET': 27,
    'CALL': 28, 'TAILCALL': 29, 'RETURN': 30, 'FORLOOP': 31, 'FORPREP': 32, 'TFORLOOP': 33,
    'SETLIST': 34, 'CLOSE': 35, 'CLOSURE': 36, 'VARARG': 37,
}
BITRK = 256
MAXsBx = 131071
emit_warn = []

def emit_proto(proto, spec, vm, path='main'):
    consts = []; cindex = {}
    def K(v):
        key = (type(v).__name__, v if not isinstance(v, float) else struct.pack('<d', v))
        if key in cindex: return cindex[key]
        consts.append(v); cindex[key] = len(consts) - 1
        return len(consts) - 1
    maxreg = [1]
    def useR(n):
        if isinstance(n, int) and 0 <= n < 250 and n > maxreg[0]: maxreg[0] = n
    def flag(v): return 0 if (v is None or v is False or v == 0) else 1

    words = []
    insns = proto.instructions
    is_vararg = 0
    i = 0
    def resolve(row, opd, rk):
        """opd descriptor -> value. rk=True means result may be a constant (RK)."""
        kind = opd[0]
        if kind == 'reg':
            r = int(row.get(opd[1], 0)); useR(r); return r
        if kind == 'imm':
            return K(row.get(opd[1])) + BITRK
        if kind == 'rk':
            fl, ks, rs = opd[1], opd[2], opd[3]
            if flag(row.get(fl)):
                return K(row.get(ks)) + BITRK
            r = int(row.get(rs, 0)); useR(r); return r
        raise ValueError('bad operand ' + repr(opd))

    while i < len(insns):
        row = insns[i]; i += 1
        op = row.get(vm.opfield)
        sp = spec.get(op, {'name': '?'})
        name = sp['name']
        def A():
            a = int(row.get(sp.get('A', -1), 0)); useR(a); return a
        word = None
        if name in ('NOP', '?'):
            emit_warn.append('%s: unhandled op %s at pc %d -> emitted RETURN' % (path, name, i))
            word = LUA_OP['RETURN'] | (0 << 6) | (1 << 14)
        elif name == 'MOVE':
            a = A(); b = int(row.get(sp['B'], 0)); useR(b)
            word = LUA_OP['MOVE'] | (a << 6) | (b << 23)
        elif name == 'LOADK':
            a = A(); word = LUA_OP['LOADK'] | (a << 6) | (K(row.get(sp['K'])) << 14)
        elif name == 'LOADBOOL':
            a = A(); b = flag(row.get(sp['B'])); c = flag(row.get(sp['C']))
            word = LUA_OP['LOADBOOL'] | (a << 6) | (c << 14) | (b << 23)
        elif name == 'LOADNIL':
            a = A(); b = int(row.get(sp['B'], 0)); useR(b)
            word = LUA_OP['LOADNIL'] | (a << 6) | (b << 23)
        elif name == 'GETUPVAL':
            a = A(); b = int(row.get(sp['B'], 0))
            word = LUA_OP['GETUPVAL'] | (a << 6) | (b << 23)
        elif name == 'SETUPVAL':
            a = A(); b = int(row.get(sp['B'], 0))
            word = LUA_OP['SETUPVAL'] | (a << 6) | (b << 23)
        elif name == 'GETGLOBAL':
            a = A(); word = LUA_OP['GETGLOBAL'] | (a << 6) | (K(row.get(sp['K'])) << 14)
        elif name == 'SETGLOBAL':
            a = A(); word = LUA_OP['SETGLOBAL'] | (a << 6) | (K(row.get(sp['K'])) << 14)
        elif name == 'GETTABLE':
            a = A(); b = int(row.get(sp['B'], 0)); useR(b); c = resolve(row, sp['C'], True)
            word = LUA_OP['GETTABLE'] | (a << 6) | (c << 14) | (b << 23)
        elif name == 'SETTABLE':
            a = A(); b = resolve(row, sp['B'], True); c = resolve(row, sp['C'], True)
            word = LUA_OP['SETTABLE'] | (a << 6) | (c << 14) | (b << 23)
        elif name == 'NEWTABLE':
            a = A(); word = LUA_OP['NEWTABLE'] | (a << 6)
        elif name == 'SELF':
            a = A(); b = int(row.get(sp['B'], 0)); useR(b); c = resolve(row, sp['C'], True)
            word = LUA_OP['SELF'] | (a << 6) | (c << 14) | (b << 23)
        elif name in ('ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW'):
            a = A(); b = resolve(row, sp['B'], True); c = resolve(row, sp['C'], True)
            word = LUA_OP[name] | (a << 6) | (c << 14) | (b << 23)
        elif name in ('UNM', 'NOT', 'LEN'):
            a = A(); b = int(row.get(sp['B'], 0)); useR(b)
            word = LUA_OP[name] | (a << 6) | (b << 23)
        elif name == 'CONCAT':
            a = A(); b = int(row.get(sp['B'], 0)); c = int(row.get(sp['C'], 0)); useR(b); useR(c)
            word = LUA_OP['CONCAT'] | (a << 6) | (c << 14) | (b << 23)
        elif name == 'JMP':
            sbx = int(row.get(sp['sBx'], 0))
            word = LUA_OP['JMP'] | ((sbx + MAXsBx) << 14)
        elif name in ('EQ', 'LT', 'LE'):
            a = flag(row.get(sp['A_flag'])); b = resolve(row, sp['B'], True); c = resolve(row, sp['C'], True)
            word = LUA_OP[name] | (a << 6) | (c << 14) | (b << 23)
        elif name == 'TEST':
            a = A(); c = flag(row.get(sp['C']))
            word = LUA_OP['TEST'] | (a << 6) | (c << 14)
        elif name == 'TESTSET':
            a = A(); b = int(row.get(sp['B'], 0)); useR(b); c = flag(row.get(sp['C']))
            word = LUA_OP['TESTSET'] | (a << 6) | (c << 14) | (b << 23)
        elif name == 'CALL':
            a = A()
            b = 0 if sp['B'][0] == 'top' else int(row.get(sp['B'][1], 0)) + 1
            c = 0 if sp['C'][0] == 'multi' else int(row.get(sp['C'][1], 0)) + 1
            word = LUA_OP['CALL'] | (a << 6) | (c << 14) | (b << 23)
        elif name == 'TAILCALL':
            a = A()
            b = 0 if sp['B'][0] == 'top' else int(row.get(sp['B'][1], 0)) + 1
            word = LUA_OP['TAILCALL'] | (a << 6) | (0 << 14) | (b << 23)
        elif name == 'RETURN':
            a = A()
            b = 0 if sp['B'][0] == 'top' else int(row.get(sp['B'][1], 0)) + 1
            word = LUA_OP['RETURN'] | (a << 6) | (b << 23)
        elif name == 'RETURN0':
            word = LUA_OP['RETURN'] | (0 << 6) | (1 << 23)
        elif name in ('FORLOOP', 'FORPREP'):
            a = A(); sbx = int(row.get(sp['sBx'], 0))
            word = LUA_OP[name] | (a << 6) | ((sbx + MAXsBx) << 14)
        elif name == 'TFORLOOP':
            a = A(); c = int(row.get(sp['C'], 0))
            word = LUA_OP['TFORLOOP'] | (a << 6) | (c << 14)
        elif name == 'SETLIST':
            a = A()
            b = 0 if sp['B'][0] == 'top' else int(row.get(sp['B'][1], 0))
            if sp['C'][0] == 'block':
                c = int(row.get(sp['C'][1], 0)) + 1
            else:
                c = int(row.get(sp['C'][1], 0)) if sp['C'][1] is not None else 1
            word = LUA_OP['SETLIST'] | (a << 6) | (c << 14) | (b << 23)
        elif name == 'CLOSE':
            a = A(); word = LUA_OP['CLOSE'] | (a << 6)
        elif name == 'VARARG':
            a = A()
            b = 0 if sp['B'][0] in ('top', 'all') else int(row.get(sp['B'][1], 0)) + 1
            is_vararg = 2
            word = LUA_OP['VARARG'] | (a << 6) | (b << 23)
        elif name == 'CLOSURE':
            a = A(); pidx = int(row.get(sp['proto'], 0)) - 1   # VM proto indices are 1-based
            word = LUA_OP['CLOSURE'] | (a << 6) | (pidx << 14)
            words.append(word)
            child = proto.subprotos[pidx] if 0 <= pidx < len(proto.subprotos) else None
            nup = child.nups if child else 0
            for _u in range(nup):
                if i >= len(insns): break
                prow = insns[i]; i += 1
                pop = prow.get(vm.opfield)
                if pop == vm.UPVCODE:
                    b = int(prow.get(vm.UPVIDX, 0))
                    words.append(LUA_OP['GETUPVAL'] | (0 << 6) | (b << 23))
                else:  # MOVECODE (capture register)
                    b = int(prow.get(vm.MOVEREG, 0))
                    words.append(LUA_OP['MOVE'] | (0 << 6) | (b << 23))
            continue
        else:
            emit_warn.append('%s: no emitter for %s' % (path, name))
            word = LUA_OP['RETURN'] | (1 << 14)
        words.append(word)

    proto._code = words
    proto._consts = consts
    proto._maxstack = max(2, min(250, maxreg[0] + 8))
    proto._is_vararg = is_vararg
    for j, sub in enumerate(proto.subprotos):
        emit_proto(sub, spec, vm, path + '.%d' % j)

# ---- bytecode serialisation (Lua 5.1, little-endian, 4-byte int, 8-byte size_t)
def u8(n): return struct.pack('<B', int(n) & 0xFF)
def u32(n): return struct.pack('<I', int(n) & 0xFFFFFFFF)
def sizet(n): return struct.pack('<I', int(n) & 0xFFFFFFFF)
def dump_string(s):
    if s is None: return sizet(0)
    b = s.encode('latin-1', 'replace') if isinstance(s, str) else s
    return sizet(len(b) + 1) + b + b'\0'
def dump_const(v):
    if v is None: return u8(0)
    if isinstance(v, bool): return u8(1) + u8(1 if v else 0)
    if isinstance(v, (int, float)): return u8(3) + struct.pack('<d', float(v))
    if isinstance(v, str): return u8(4) + dump_string(v)
    emit_warn.append('unsupported const type ' + type(v).__name__); return u8(0)
def dump_proto(p, is_main):
    out = []
    out.append(dump_string('@deobfuscated' if is_main else None))
    out.append(u32(0)); out.append(u32(0))          # line defined / last
    out.append(u8(p.nups))
    out.append(u8(p.params))
    out.append(u8(2 if is_main else p._is_vararg))
    out.append(u8(p._maxstack))
    out.append(u32(len(p._code)))
    for w in p._code: out.append(u32(w))
    out.append(u32(len(p._consts)))
    for c in p._consts: out.append(dump_const(c))
    out.append(u32(len(p.subprotos)))
    for sub in p.subprotos: out.append(dump_proto(sub, False))
    out.append(u32(0)); out.append(u32(0)); out.append(u32(0))   # stripped debug
    return b''.join(out)
def dump_chunk(main):
    header = b'\x1bLua' + u8(0x51) + u8(0) + u8(1) + u8(4) + u8(4) + u8(4) + u8(8) + u8(0)
    return header + dump_proto(main, True)


def main():
    src_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else re.sub(r'\.lua$', '', src_path) + '.decompiled.lua'
    src = open(src_path, encoding='utf-8', errors='replace').read()
    vm = analyse_vm(src)
    spec, warns = classify(vm)
    d1, d2, d3 = detect_delimiters(src)
    layout = detect_layout(vm, src, d1)
    for s in spec.values():
        if s['name'] == 'CLOSURE' and 'nups_slot' in s:
            layout['nups'] = s['nups_slot']
    blob = extract_blob(src)
    entry = extract_entry_expr(src)
    tree = LuaLit(entry, blob).parse()
    proto = build_proto(tree, vm, layout, d1, d2, d3)

    from collections import Counter
    def count(p, acc):
        acc[0] += 1; acc[1] += len(p.instructions)
        for s in p.subprotos: count(s, acc)
        return acc
    acc = count(proto, [0, 0])
    sys.stderr.write('[devirt] delims=%r layout=%s  protos=%d instructions=%d unknown_ops=%d\n' % (
        (d1, d2, d3), layout, acc[0], acc[1], len(warns)))
    for lo, ns in warns:
        sys.stderr.write('  WARN unknown handler [%d]: %s\n' % (lo, ns[:90]))

    # ---- pseudo (devirtualized) listing ----
    pseudo_path = re.sub(r'\.lua$', '', out_path) + '.pseudo.txt'
    with open(pseudo_path, 'w', encoding='utf-8') as fh:
        def dump_listing(p, name):
            fh.write('\n-- proto %s : params=%d nups=%d instrs=%d\n' % (name, p.params, p.nups, len(p.instructions)))
            for pc, row in enumerate(p.instructions):
                op = row.get(vm.opfield)
                sp = spec.get(op, {'name': '?'})
                fh.write('  [%3d] %-9s %s\n' % (pc, sp['name'], {k: v for k, v in sorted(row.items()) if k != vm.opfield}))
            for j, sub in enumerate(p.subprotos):
                dump_listing(sub, name + '.%d' % j)
        dump_listing(proto, 'main')

    # ---- emit bytecode ----
    emit_proto(proto, spec, vm)
    bytecode = dump_chunk(proto)
    luac_path = re.sub(r'\.lua$', '', out_path) + '.luac'
    with open(luac_path, 'wb') as fh:
        fh.write(bytecode)
    sys.stderr.write('[devirt] wrote pseudo listing -> %s\n' % pseudo_path)
    sys.stderr.write('[devirt] wrote bytecode -> %s  (%d emit warnings)\n' % (luac_path, len(emit_warn)))
    for w in emit_warn[:20]:
        sys.stderr.write('  ' + w + '\n')

    # ---- run unluac ----
    jar = None
    for cand in ['unluac.jar', os.path.join(os.path.dirname(src_path) or '.', 'unluac.jar')]:
        if os.path.isfile(cand): jar = cand; break
    if not jar:
        sys.stderr.write('[devirt] unluac.jar not found; decompile with: java -jar unluac.jar "%s" > "%s"\n' % (luac_path, out_path))
        return
    try:
        res = subprocess.run(['java', '-jar', jar, luac_path], capture_output=True, timeout=300)
        decompiled = res.stdout.decode('utf-8', 'replace')
    except Exception as ex:
        sys.stderr.write('[devirt] unluac failed: %s\n' % ex); return
    if not decompiled.strip():
        sys.stderr.write('[devirt] unluac produced no output; stderr:\n%s\n' % res.stderr.decode('utf-8', 'replace')[:500]); return
    header = '-- Devirtualized by devirt.py + unluac\n-- Source: %s\n\n' % src_path
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(header + decompiled)
    sys.stderr.write('[devirt] wrote runnable Lua -> %s\n' % out_path)

if __name__ == '__main__':
    main()
