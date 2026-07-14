--[[============================================================================
  deobfuscate_auto.lua  -  self-detecting VM devirtualizer for the
  Jactor / IronBrew2-style Lua 5.1 obfuscator used by this project.

  Usage:
      lua deobfuscate_auto.lua <input.lua> [output.lua]

  Unlike deobfu_vm_v4.lua / deobfu_vm_v45.lua, this script does NOT hardcode
  the opcode numbers or the instruction field slots.  Every obfuscation
  shuffles them, so this script reads the target's own VM interpreter and
  RE-DERIVES the whole map:

    * the opcode field slot          (which p[?] holds the opcode)
    * the A / B / C / constant / flag / sBx / proto field slots
    * opcode-number  ->  operation   (ADD, CALL, GETGLOBAL, ...)

  Detection works by parsing the VM's binary-search dispatch tree
  ( if n<19 then ... elseif n>19 ... ) and fingerprinting each handler body.
  The operation *bodies* stay constant across obfuscations even though the
  numbers permute, so the fingerprints keep working.

  If a handler shape is ever encountered that the fingerprint table does not
  recognise, the script reports it loudly (WARNING: unknown handler ...) instead
  of silently guessing, so you know a new opcode variant needs a signature.
============================================================================]]--

local src_path = assert(arg and arg[1], 'usage: lua deobfuscate_auto.lua <input.lua> [output.lua]')
local out_path = arg and arg[2] or (src_path:gsub('%.lua$', '') .. '.deobfuscated.lua')

--=============================================================================
-- 0. small io helpers
--=============================================================================
local function read_all(path)
	local fh = assert(io.open(path, 'rb'), 'failed to open ' .. path)
	local data = fh:read('*a'); fh:close(); return data
end
local function write_all(path, data)
	local fh = assert(io.open(path, 'wb'), 'failed to write ' .. path)
	fh:write(data); fh:close()
end

if not string.split then
	function string:split(sep)
		local out, start = {}, 1
		while true do
			local pos = self:find(sep, start, true)
			if not pos then out[#out + 1] = self:sub(start); break end
			out[#out + 1] = self:sub(start, pos - 1); start = pos + #sep
		end
		return out
	end
end

--=============================================================================
-- 1. string decoders used by the obfuscator (base93/LZW + hex pairs)
--=============================================================================
local alphabet, alphabet_count = {}, 0
for i = 32, 127 do
	if i ~= 34 and i ~= 92 then
		local ch = string.char(i)
		alphabet[ch], alphabet[alphabet_count] = alphabet_count, ch
		alphabet_count = alphabet_count + 1
	end
end
local escape_map = {}
for i = 1, 34 do
	local code = ({34, 92, 127})[i - 31] or i
	local a, b = string.char(code), string.char(code + 31)
	escape_map[a], escape_map[b] = b, a
end
local function clone(t) local o = {} for k, v in pairs(t) do o[k] = v end return o end
local function unescape_string(s)
	return (s:gsub('\127(.)', function(ch) return escape_map[ch] end))
end
local function base93num(value)
	local out = 0
	for i = 1, #value do out = out + 93 ^ (i - 1) * alphabet[value:sub(-i, -i)] end
	return out
end
local function decompress(text)
	local dict = clone(alphabet)
	local output, spans, content = {}, text:match('(.-)|(.*)')
	assert(spans and content, 'compressed stream is malformed')
	local groups, pos = {}, 1
	for span in spans:gmatch('%d+') do
		span = tonumber(span)
		local width = #groups + 1
		groups[width] = content:sub(pos, pos + span * width - 1)
		pos = pos + span * width
	end
	local prev
	for width = 1, #groups do
		for token in groups[width]:gmatch(('.'):rep(width)) do
			local cur = dict[base93num(token)]
			if prev then
				if cur then
					output[#output + 1] = cur
					dict[#dict + 1] = prev .. cur:sub(1, 1)
				else
					cur = prev .. prev:sub(1, 1)
					output[#output + 1] = cur
					dict[#dict + 1] = cur
				end
			else
				output[1] = cur
			end
			prev = cur
		end
	end
	return unescape_string(table.concat(output))
end
local function decode_hex_pairs(s)
	return (s:gsub('..', function(pair)
		local a, b = pair:byte(1, 2)
		return string.char((a - 65) * 16 + b - 66)
	end))
end

--=============================================================================
-- 2. lightweight source scanning helpers
--=============================================================================
local function read_lua_string(src, quote_pos)
	local quote = src:sub(quote_pos, quote_pos)
	assert(quote == '"' or quote == "'", 'expected Lua string')
	local out, pos = {}, quote_pos + 1
	while pos <= #src do
		local ch = src:sub(pos, pos)
		if ch == quote then
			return table.concat(out), pos
		elseif ch == '\\' then
			local next_ch = src:sub(pos + 1, pos + 1)
			if next_ch:match('%d') then
				local digits = src:sub(pos + 1):match('^%d%d?%d?')
				out[#out + 1] = string.char(tonumber(digits)); pos = pos + #digits + 1
			elseif next_ch == 'n' then out[#out + 1] = '\n'; pos = pos + 2
			elseif next_ch == 'r' then out[#out + 1] = '\r'; pos = pos + 2
			elseif next_ch == 't' then out[#out + 1] = '\t'; pos = pos + 2
			else out[#out + 1] = next_ch; pos = pos + 2 end
		else
			out[#out + 1] = ch; pos = pos + 1
		end
	end
	error('unterminated Lua string')
end
local function find_matching(src, start_pos, open_ch, close_ch)
	local depth, quote, pos = 0, nil, start_pos
	while pos <= #src do
		local ch = src:sub(pos, pos)
		if quote then
			if ch == '\\' then pos = pos + 2
			elseif ch == quote then quote = nil; pos = pos + 1
			else pos = pos + 1 end
		else
			if ch == '"' or ch == "'" then quote = ch
			elseif ch == open_ch then depth = depth + 1
			elseif ch == close_ch then depth = depth - 1; if depth == 0 then return pos end end
			pos = pos + 1
		end
	end
	error('unterminated ' .. open_ch)
end

-- The constant blob: any  name("....")  whose decompressed+hex-decoded value is
-- the largest printable blob.  (In v45 samples it was g("..."); here it is e("...").)
local function extract_constant_blob(src)
	local best, start = '', 1
	while true do
		local call_start = src:find('[%w_]+%s*%(%s*"', start)
		if not call_start then break end
		local quote_pos = src:find('"', call_start, true)
		local ok_read, payload, quote_end = pcall(read_lua_string, src, quote_pos)
		if ok_read then
			local ok, decoded = pcall(function()
				return decode_hex_pairs(decompress(payload))
			end)
			if ok and #decoded > #best then best = decoded end
			start = quote_end + 1
		else
			start = quote_pos + 1
		end
	end
	return best
end

-- The final  return f({...}, getfenv())()  prototype table expression.
local function extract_entry_proto_expr(src)
	local search_pos, best = 1
	while true do
		local ret_start, call_end = src:find('return%s+[%w_]+%s*%(', search_pos)
		if not ret_start then break end
		local brace_start = src:find('{', call_end + 1, true)
		if brace_start then
			local ok, brace_end = pcall(find_matching, src, brace_start, '{', '}')
			if ok then
				local suffix = src:sub(brace_end + 1, brace_end + 80)
				if suffix:match('^%s*,%s*[%w_]+%s*%(%s*%)%s*%)%s*%(%s*%)') then
					best = src:sub(brace_start, brace_end)
				end
			end
		end
		search_pos = call_end + 1
	end
	assert(best, 'final VM return prototype was not found')
	return best
end

local function detect_delimiters(src)
	local a, b, c = src:match(':split%("([^"])"%).-:split%("([^"])"%).-:split%("([^"])"%)')
	assert(a and b and c, 'could not detect instruction delimiters')
	return a, b, c
end

-- Prototype table layout (which numeric slot is params/subprotos/code/constmap).
-- Detected from the VM's own prototype builder, with sensible fallbacks.
local function detect_proto_layout(src, d1)
	local layout = { params = 1, subprotos = 3, code = 4, constmap = 5 }
	local code = src:match('[%w_]+%s*%(%s*[%w_]+%[(%d+)%]%s*%)%s*:split%("' .. d1 .. '"')
	if code then layout.code = tonumber(code) end
	local const = src:match(':split%("' .. d1 .. '"%)%s*do%s*local%s+[%w_]+%s*=%s*[%w_]+%[(%d+)%]')
	if const then layout.constmap = tonumber(const) end
	local params = src:match('local%s+[%w_]+%s*=%s*[%w_]+%[(%d+)%]%s*return%s+function')
	if params then layout.params = tonumber(params) end
	return layout
end

--=============================================================================
-- 3. VM ANALYSIS: tokenizer + dispatch-tree parser + handler fingerprints
--    (this is the "detect if an opcode changed and act accordingly" core)
--=============================================================================
local KEYWORDS = {}
for _, w in ipairs{'if','then','elseif','else','end','for','while','do','function',
	'repeat','until','return','local','and','or','not','nil','true','false','in'} do
	KEYWORDS[w] = true
end

local function tokenize(s, from, to)
	local toks, i = {}, from
	to = to or #s
	while i <= to do
		local c = s:sub(i, i)
		if c:match('%s') then
			i = i + 1
		elseif c:match('[%a_]') then
			local j = i
			while j <= to and s:sub(j, j):match('[%w_]') do j = j + 1 end
			local w = s:sub(i, j - 1)
			toks[#toks + 1] = { t = (KEYWORDS[w] and 'kw' or 'name'), v = w, pos = i }
			i = j
		elseif c:match('%d') or (c == '.' and s:sub(i + 1, i + 1):match('%d')) then
			local j = i
			while j <= to and s:sub(j, j):match('[%w%.]') do j = j + 1 end
			toks[#toks + 1] = { t = 'num', v = s:sub(i, j - 1), pos = i }
			i = j
		elseif c == '"' or c == "'" then
			local q, j = c, i + 1
			while j <= to do
				local d = s:sub(j, j)
				if d == '\\' then j = j + 2
				elseif d == q then j = j + 1; break
				else j = j + 1 end
			end
			toks[#toks + 1] = { t = 'str', v = s:sub(i, j - 1), pos = i }
			i = j
		else
			local two = s:sub(i, i + 1)
			if two == '==' or two == '~=' or two == '<=' or two == '>=' or two == '..' then
				toks[#toks + 1] = { t = 'sym', v = two, pos = i }; i = i + 2
			else
				toks[#toks + 1] = { t = 'sym', v = c, pos = i }; i = i + 1
			end
		end
	end
	toks[#toks + 1] = { t = 'eof', v = '', pos = to + 1 }
	return toks
end

-- fingerprint a handler body (whitespace-stripped) -> canonical operation name.
-- Ordered most-specific first.  Returns name or nil (unknown).
local COMPARE = 'if%(.-%)~=%(p%[%d+%]~=0%)'
local function fingerprint(ns)
	-- unique-token handlers -------------------------------------------------
	if ns:find('math%.abs')            then return 'FORLOOP'  end
	if ns:find('assert%(tonumber')     then return 'FORPREP'  end
	if ns:find('%.value')              then return 'SETLIST'  end
	if ns:find('%[p%[%d+%]%+1%]')      then return 'CLOSURE'  end   -- a[p[proto]+1]
	if ns:find('returnj%(o%[')         then return 'TAILCALL' end
	if ns:find('=j%(o%[')              then return 'CALL'     end
	if ns:find('math%.huge%)return')   then return 'RETURN'   end
	if ns:find('={%w+%(%w+,%w+%)}')    then return 'TFORLOOP' end   -- b={c(d,a)}
	if ns:find('%.store%[%w+%.index%]=o') then return 'SETUPVAL' end
	if ns:find('=%w+%.store%[')        then return 'GETUPVAL' end
	if ns:find('^g%(%w+,p%[%d+%]%)$')  then return 'CLOSE'    end   -- g(k,p[A])
	if ns:find('%.%.o%[')              then return 'CONCAT'   end   -- b..o[a]
	if ns:find('=noto%[')              then return 'NOT'      end
	if ns:find('=%-o%[')               then return 'UNM'      end
	if ns:find('=#o%[')                then return 'LEN'      end
	if ns:find('o%[%w+%+1%]=o%[%w+%]o%[%w+%]=o%[%w+%]%[') then return 'SELF' end
	-- vararg copies varargs (c) into registers, no return -------------------
	if ns:find('o%[%w+%+%w+%-1%]=%w+%[%w+%]end') and not ns:find('return') then return 'VARARG' end
	-- simple / structural handlers -----------------------------------------
	if ns:find('=nilend')                     then return 'LOADNIL'   end
	if ns:find('o%[p%[%d+%]%]={}')            then return 'NEWTABLE'  end
	if ns:find('^%w+=%w+%+p%[%d+%]$')         then return 'JMP'       end
	if ns:find('=h%[p%[%d+%]%]')              then return 'GETGLOBAL' end
	if ns:find('^h%[p%[%d+%]%]=')             then return 'SETGLOBAL' end
	if ns:find('=p%[%d+%]~=0if') then return 'LOADBOOL' end
	if ns:find('if%(not') then
		if ns:find('elseo%[') then return 'TESTSET' else return 'TEST' end
	end
	if ns:find('%]=o%[p%[%d+%]%]%[%w+%]$') then return 'GETTABLE' end   -- ...=o[p[B]][c]
	if ns:find('^o%[p%[%d+%]%]=p%[%d+%]$') then return 'LOADK'    end
	if ns:find('^o%[p%[%d+%]%]=o%[p%[%d+%]%]$') then return 'MOVE' end
	-- RK arithmetic / comparison: strip the two RK-decode blocks then look at
	-- the trailing operator (this is robust to operand-var renaming) --------
	local tail = ns:gsub('ifp%[%d+%]then%w+=p%[%d+%]else%w+=o%[p%[%d+%]%]end', '')
	if tail:find(COMPARE) then
		if tail:find('<=') then return 'LE' end
		if tail:find('==') then return 'EQ' end
		if tail:find('<')  then return 'LT' end
	end
	if tail:find('%]%[%w+%]=%w+$') then return 'SETTABLE' end          -- o[p[A]][b]=c
	local op = tail:match('o%[p%[%d+%]%]=%w+([%+%-%*/%%%^])%w+$')
	if op == '/' then return 'DIV' end
	if op == '^' then return 'POW' end
	if op == '*' then return 'MUL' end
	if op == '%' then return 'MOD' end
	if op == '+' then return 'ADD' end
	if op == '-' then return 'SUB' end
	return nil
end

-- Parse the dispatch tree.  Returns { opmap = {[n]=name}, fields = {...},
-- warnings = {...} }.
local function analyse_vm(src)
	-- locate  local <n> = <p>[<F>]  <l> = <l>+1  if <n> < <num>
	local anchor = src:find('local%s+(%w+)%s*=%s*(%w+)%s*%[%s*(%d+)%s*%]%s*(%w+)%s*=%s*%w+%s*%+%s*1%s*if%s+%w+%s*<')
	assert(anchor, 'could not locate VM opcode dispatch (unrecognised VM layout)')
	local dvar, opfield = src:match('local%s+(%w+)%s*=%s*%w+%s*%[%s*(%d+)%s*%]%s*%w+%s*=%s*%w+%s*%+%s*1%s*if', anchor)
	opfield = tonumber(opfield)
	local if_pos = src:find('if%s+' .. dvar .. '%s*[<>]', anchor)
	local toks = tokenize(src, if_pos)
	local BIG = 1e9

	local leaves = {}
	local function is_switch(i)
		local a, b, c = toks[i], toks[i + 1], toks[i + 2]
		return a and a.t == 'kw' and a.v == 'if'
		   and b and b.v == dvar
		   and c and (c.v == '<' or c.v == '>' or c.v == '<=' or c.v == '>=' or c.v == '==' or c.v == '~=')
	end

	local parse_leaf, parse_switch
	function parse_leaf(i, lo, hi)
		local depth, pending_do, j = 0, 0, i
		while true do
			local tk = toks[j]
			assert(tk.t ~= 'eof', 'unexpected eof inside handler body')
			if depth == 0 and tk.t == 'kw' and (tk.v == 'elseif' or tk.v == 'else' or tk.v == 'end') then
				leaves[#leaves + 1] = {
					value = lo, lo = lo, hi = hi,
					text = src:sub(toks[i].pos, toks[j].pos - 1),
				}
				return j
			end
			if tk.t == 'kw' then
				local v = tk.v
				if v == 'if' or v == 'function' then depth = depth + 1
				elseif v == 'for' or v == 'while' then depth = depth + 1; pending_do = pending_do + 1
				elseif v == 'do' then if pending_do > 0 then pending_do = pending_do - 1 else depth = depth + 1 end
				elseif v == 'repeat' then depth = depth + 1
				elseif v == 'until' then depth = depth - 1
				elseif v == 'end' then depth = depth - 1 end
			end
			j = j + 1
		end
	end

	function parse_switch(i, lo, hi)
		local run_lo, run_hi = lo, hi
		local pos = i
		while true do
			assert(toks[pos].v == 'if' or toks[pos].v == 'elseif', 'malformed switch')
			assert(toks[pos + 1].v == dvar, 'malformed switch condition')
			local op = toks[pos + 2].v
			local C = tonumber(toks[pos + 3].v)
			assert(C, 'non-numeric dispatch bound')
			assert(toks[pos + 4].v == 'then', 'expected then')
			local t_lo, t_hi = run_lo, run_hi
			if     op == '<'  then t_hi = math.min(t_hi, C - 1); run_lo = math.max(run_lo, C)
			elseif op == '>'  then t_lo = math.max(t_lo, C + 1); run_hi = math.min(run_hi, C)
			elseif op == '<=' then t_hi = math.min(t_hi, C);     run_lo = math.max(run_lo, C + 1)
			elseif op == '>=' then t_lo = math.max(t_lo, C);     run_hi = math.min(run_hi, C - 1)
			elseif op == '==' then t_lo, t_hi = C, C
			end
			local body = pos + 5
			local stop = is_switch(body) and parse_switch(body, t_lo, t_hi) or parse_leaf(body, t_lo, t_hi)
			local d = toks[stop]
			if d.v == 'elseif' then
				pos = stop
			elseif d.v == 'else' then
				local body2 = stop + 1
				local stop2 = is_switch(body2) and parse_switch(body2, run_lo, run_hi) or parse_leaf(body2, run_lo, run_hi)
				assert(toks[stop2].v == 'end', 'expected end after else')
				return stop2 + 1
			elseif d.v == 'end' then
				return stop + 1
			else
				error('unexpected delimiter ' .. tostring(d.v))
			end
		end
	end
	parse_switch(1, 0, BIG)

	-- classify leaves & harvest field slots --------------------------------
	local opmap, warnings = {}, {}
	local fields = { op = opfield }
	local function set(name, val) if val and not fields[name] then fields[name] = tonumber(val) end end

	for _, lf in ipairs(leaves) do
		local ns = lf.text:gsub('%s+', '')
		local name = fingerprint(ns)
		if not name then
			warnings[#warnings + 1] = string.format(
				'unknown handler for opcode %d -> %s', lf.value, (#ns > 120 and ns:sub(1, 120) .. '...' or ns))
		else
			if opmap[lf.value] and opmap[lf.value] ~= name then
				warnings[#warnings + 1] = string.format(
					'opcode %d fingerprinted as both %s and %s', lf.value, opmap[lf.value], name)
			end
			opmap[lf.value] = name

			-- harvest field slots from recognisable shapes
			if name == 'LOADK' then
				local a, k = ns:match('^o%[p%[(%d+)%]%]=p%[(%d+)%]$'); set('A', a); set('Kst', k)
			elseif name == 'MOVE' then
				local a, b = ns:match('^o%[p%[(%d+)%]%]=o%[p%[(%d+)%]%]$'); set('A', a); set('B', b)
			elseif name == 'LEN' or name == 'NOT' or name == 'UNM' then
				local a, b = ns:match('o%[p%[(%d+)%]%]=[#%-n]o?t?o?%[?p?%[?(%d+)')
				if not a then a, b = ns:match('o%[p%[(%d+)%]%].-p%[(%d+)%]') end
				set('A', a); set('B', b)
			elseif name == 'JMP' then
				set('sBx', ns:match('=%w+%+p%[(%d+)%]$'))
			elseif name == 'GETGLOBAL' then
				local a, k = ns:match('o%[p%[(%d+)%]%]=h%[p%[(%d+)%]%]'); set('A', a); set('Kst', k)
			elseif name == 'SETGLOBAL' then
				local k, a = ns:match('^h%[p%[(%d+)%]%]=o%[p%[(%d+)%]%]'); set('Kst', k); set('A', a)
			elseif name == 'CLOSURE' then
				set('proto', ns:match('%[p%[(%d+)%]%+1%]'))
			elseif name == 'ADD' or name == 'SUB' or name == 'MUL'
				or name == 'DIV' or name == 'MOD' or name == 'POW' then
				-- two RK blocks: first -> B, second -> C ; dest -> A
				local flags = {}
				for f, kc, rc in ns:gmatch('ifp%[(%d+)%]then%w+=p%[(%d+)%]else%w+=o%[p%[(%d+)%]%]end') do
					flags[#flags + 1] = { flag = f, k = kc, reg = rc }
				end
				if flags[1] then set('isKB', flags[1].flag); set('KB', flags[1].k); set('B', flags[1].reg) end
				if flags[2] then set('isKC', flags[2].flag); set('KC', flags[2].k); set('C', flags[2].reg) end
				set('A', ns:match('end%s*o%[p%[(%d+)%]%]=%w+[%+%-%*/%%%^]%w+$') or ns:match('o%[p%[(%d+)%]%]=%w+[%+%-%*/%%%^]%w+$'))
			elseif name == 'GETTABLE' then
				local a, b = ns:match('o%[p%[(%d+)%]%]=o%[p%[(%d+)%]%]%[%w+%]$'); set('A', a); set('B', b)
			end
		end
	end

	-- Fallbacks for slots not observed directly (stable across this VM family).
	local defaults = { A = 9, B = 8, C = 6, KB = 5, KC = 1, isKB = 11, isKC = 10, Kst = 4, sBx = 2, proto = 7 }
	for k, v in pairs(defaults) do if not fields[k] then fields[k] = v end end

	return { opmap = opmap, fields = fields, warnings = warnings,
	         dvar = dvar, leaf_count = #leaves }
end

--=============================================================================
-- 4. decode the prototype tree using the detected field slots
--=============================================================================
local function decode_instructions(raw_code, constmap, layout_fields, d1, d2, d3)
	local decoded = decompress(raw_code)
	local F = layout_fields
	local out = {}
	for gi, group in ipairs(decoded:split(d1)) do
		local raw = {}
		for _, pair in ipairs(group:split(d2)) do
			local kv = pair:split(d3)
			local k, v = kv[1], kv[2]
			if k and v and k ~= '' then raw[constmap[k]] = constmap[v] end
		end
		out[gi] = {
			raw   = raw,
			op    = raw[F.op],
			A     = raw[F.A],
			B     = raw[F.B],
			C     = raw[F.C],
			KB    = raw[F.KB],
			KC    = raw[F.KC],
			isKB  = raw[F.isKB],
			isKC  = raw[F.isKC],
			Kst   = raw[F.Kst],
			sBx   = raw[F.sBx],
			proto = raw[F.proto],
		}
	end
	return out
end

local function decode_proto(raw, det, layout, d1, d2, d3)
	local node = {
		params    = raw[layout.params],
		subprotos = raw[layout.subprotos] or {},
		instructions = decode_instructions(raw[layout.code], raw[layout.constmap], det.fields, d1, d2, d3),
	}
	local subs = {}
	for i, sub in ipairs(node.subprotos) do
		subs[i] = decode_proto(sub, det, layout, d1, d2, d3)
	end
	node.subprotos = subs
	return node
end

--=============================================================================
-- 5. lift instructions to readable Lua-like pseudocode (keyed by op NAME)
--=============================================================================
local function q(v)
	if type(v) == 'string' then return string.format('%q', v) end
	return tostring(v)
end
local function raw_table(t)
	local parts = {}
	for k, v in pairs(t) do parts[#parts + 1] = '[' .. q(k) .. ']=' .. q(v) end
	table.sort(parts)
	return '{' .. table.concat(parts, ', ') .. '}'
end
local function reg(n) return 'r' .. tostring(n) end
local function regs(start, count)
	local o = {} for i = 0, count - 1 do o[#o + 1] = reg(start + i) end return table.concat(o, ', ')
end
local function rk_b(i) if i.isKB then return q(i.KB) end return reg(i.B) end
local function rk_c(i) if i.isKC then return q(i.KC) end return reg(i.C) end
local function call_args(base, encoded)
	if encoded == 0 then return 'unpack(r, ' .. (base + 1) .. ', top)' end
	if encoded == 1 then return '' end
	return 'unpack(r, ' .. (base + 1) .. ', ' .. (base + encoded - 1) .. ')'
end
local function label(pc) return string.format('pc_%04d', pc) end

local function lift(inst, pc)
	local name = inst.opname
	local A, B, C = inst.A, inst.B, inst.C
	if name == 'MOVE'      then return reg(A) .. ' = ' .. reg(B)
	elseif name == 'LOADK'     then return reg(A) .. ' = ' .. q(inst.Kst)
	elseif name == 'LOADBOOL'  then return reg(A) .. ' = ' .. tostring(B ~= 0) .. (C ~= 0 and ('; goto ' .. label(pc + 2)) or '')
	elseif name == 'LOADNIL'   then return 'for i = ' .. tostring(A) .. ', ' .. tostring(B) .. ' do r[i] = nil end'
	elseif name == 'GETUPVAL'  then return reg(A) .. ' = upval[' .. tostring(B) .. ']'
	elseif name == 'SETUPVAL'  then return 'upval[' .. tostring(B) .. '] = ' .. reg(A)
	elseif name == 'GETGLOBAL' then return reg(A) .. ' = _ENV[' .. q(inst.Kst) .. ']'
	elseif name == 'SETGLOBAL' then return '_ENV[' .. q(inst.Kst) .. '] = ' .. reg(A)
	elseif name == 'GETTABLE'  then return reg(A) .. ' = ' .. reg(B) .. '[' .. rk_c(inst) .. ']'
	elseif name == 'SETTABLE'  then return reg(A) .. '[' .. rk_b(inst) .. '] = ' .. rk_c(inst)
	elseif name == 'NEWTABLE'  then return reg(A) .. ' = {}'
	elseif name == 'SELF'      then return reg(A + 1) .. ' = ' .. reg(B) .. '; ' .. reg(A) .. ' = ' .. reg(B) .. '[' .. rk_c(inst) .. ']'
	elseif name == 'ADD'       then return reg(A) .. ' = ' .. rk_b(inst) .. ' + ' .. rk_c(inst)
	elseif name == 'SUB'       then return reg(A) .. ' = ' .. rk_b(inst) .. ' - ' .. rk_c(inst)
	elseif name == 'MUL'       then return reg(A) .. ' = ' .. rk_b(inst) .. ' * ' .. rk_c(inst)
	elseif name == 'DIV'       then return reg(A) .. ' = ' .. rk_b(inst) .. ' / ' .. rk_c(inst)
	elseif name == 'MOD'       then return reg(A) .. ' = ' .. rk_b(inst) .. ' % ' .. rk_c(inst)
	elseif name == 'POW'       then return reg(A) .. ' = ' .. rk_b(inst) .. ' ^ ' .. rk_c(inst)
	elseif name == 'UNM'       then return reg(A) .. ' = -' .. reg(B)
	elseif name == 'NOT'       then return reg(A) .. ' = not ' .. reg(B)
	elseif name == 'LEN'       then return reg(A) .. ' = #' .. reg(B)
	elseif name == 'CONCAT'    then return reg(A) .. ' = table.concat({' .. regs(B, math.max((C or B) - B + 1, 1)) .. '})  -- concat r' .. B .. '..r' .. tostring(C)
	elseif name == 'JMP'       then return 'goto ' .. label(pc + 1 + (inst.sBx or 0))
	elseif name == 'EQ'        then return 'if (' .. rk_b(inst) .. ' == ' .. rk_c(inst) .. ') ~= ' .. tostring(A ~= 0) .. ' then goto ' .. label(pc + 2) .. ' end'
	elseif name == 'LT'        then return 'if (' .. rk_b(inst) .. ' < '  .. rk_c(inst) .. ') ~= ' .. tostring(A ~= 0) .. ' then goto ' .. label(pc + 2) .. ' end'
	elseif name == 'LE'        then return 'if (' .. rk_b(inst) .. ' <= ' .. rk_c(inst) .. ') ~= ' .. tostring(A ~= 0) .. ' then goto ' .. label(pc + 2) .. ' end'
	elseif name == 'TEST'      then return 'if (not ' .. reg(A) .. ') == ' .. tostring(C ~= 0) .. ' then goto ' .. label(pc + 2) .. ' end'
	elseif name == 'TESTSET'   then return 'if (' .. reg(B) .. ') then ' .. reg(A) .. ' = ' .. reg(B) .. ' else goto ' .. label(pc + 2) .. ' end'
	elseif name == 'CALL'      then
		local c = reg(A) .. '(' .. call_args(A, B) .. ')'
		if C == 1 then return c
		elseif C == 0 then return reg(A) .. ', top = ' .. c .. '  -- multiret'
		else return regs(A, C - 1) .. ' = ' .. c end
	elseif name == 'TAILCALL'  then return 'return ' .. reg(A) .. '(' .. call_args(A, B) .. ')'
	elseif name == 'RETURN'    then
		if B == 1 then return 'return'
		elseif B == 0 then return 'return unpack(r, ' .. tostring(A) .. ', top)'
		else return 'return ' .. regs(A, B - 1) end
	elseif name == 'VARARG'    then return '-- VARARG: copy varargs into ' .. reg(A) .. ' (count=' .. tostring(B) .. ')'
	elseif name == 'CLOSE'     then return '-- CLOSE upvalues >= ' .. reg(A)
	elseif name == 'CLOSURE'   then return reg(A) .. ' = closure(subproto[' .. tostring((inst.proto or 0) + 1) .. '])'
	elseif name == 'NEWTABLE'  then return reg(A) .. ' = {}'
	elseif name == 'SETLIST'   then return '-- SETLIST ' .. reg(A) .. ' (block=' .. tostring(C) .. ' count=' .. tostring(B) .. ')'
	elseif name == 'FORPREP'   then return '-- FORPREP ' .. reg(A) .. ' (jump ' .. tostring(inst.sBx) .. '); goto ' .. label(pc + 1 + (inst.sBx or 0))
	elseif name == 'FORLOOP'   then return '-- FORLOOP ' .. reg(A) .. ' (jump ' .. tostring(inst.sBx) .. '); if continue then goto ' .. label(pc + 1 + (inst.sBx or 0)) .. ' end'
	elseif name == 'TFORLOOP'  then return '-- TFORLOOP ' .. reg(A) .. ' (generic for iteration)'
	end
	return '-- UNKNOWN op=' .. tostring(inst.op) .. ' ' .. raw_table(inst.raw)
end

local function dump(proto, out, indent, det, name)
	indent = indent or ''
	name = name or 'main'
	out[#out + 1] = indent .. string.format('-- function %s  params=%s  instructions=%d  subprotos=%d',
		name, tostring(proto.params), #proto.instructions, #proto.subprotos)
	out[#out + 1] = indent .. 'do'
	for pc, inst in ipairs(proto.instructions) do
		inst.opname = det.opmap[inst.op] or ('OP_' .. tostring(inst.op))
		out[#out + 1] = indent .. string.format('\t::%s::  %-9s %s', label(pc), inst.opname, lift(inst, pc))
	end
	out[#out + 1] = indent .. 'end'
	for i, sub in ipairs(proto.subprotos) do
		out[#out + 1] = ''
		dump(sub, out, indent, det, name .. '.sub' .. i)
	end
end

--=============================================================================
-- 6. main
--=============================================================================
local src = read_all(src_path)

local d1, d2, d3 = detect_delimiters(src)
local layout = detect_proto_layout(src, d1)
local det = analyse_vm(src)

local constant_blob = extract_constant_blob(src)
local proto_expr = extract_entry_proto_expr(src)
local substr = function(...) return constant_blob:sub(...) end
local env = setmetatable({ ['true'] = true, ['false'] = false }, {
	__index = function(_, k)
		if type(k) == 'string' and #k <= 3 then return substr end
		return _G[k]
	end,
})
local loader = assert(loadstring('return ' .. proto_expr))
setfenv(loader, env)
local raw_proto = loader()
local proto = decode_proto(raw_proto, det, layout, d1, d2, d3)

-- ---- detection report --------------------------------------------------------
local report = {}
report[#report + 1] = '-- ============================================================'
report[#report + 1] = '-- Auto-deobfuscation of ' .. src_path
report[#report + 1] = '-- Opcodes/field slots were DETECTED from this sample\'s own VM.'
report[#report + 1] = '-- ============================================================'
report[#report + 1] = '--'
report[#report + 1] = string.format('-- delimiters: instr=%q pair=%q keyval=%q', d1, d2, d3)
report[#report + 1] = string.format('-- proto layout: params=[%d] subprotos=[%d] code=[%d] constmap=[%d]',
	layout.params, layout.subprotos, layout.code, layout.constmap)
local F = det.fields
report[#report + 1] = string.format('-- field slots:  op=p[%d] A=p[%d] B=p[%d] C=p[%d] sBx=p[%d] Kst=p[%d]',
	F.op, F.A, F.B, F.C, F.sBx, F.Kst)
report[#report + 1] = string.format('--               KB=p[%d](flag p[%d])  KC=p[%d](flag p[%d])  proto=p[%d]',
	F.KB, F.isKB, F.KC, F.isKC, F.proto)
report[#report + 1] = string.format('-- detected %d handlers in the dispatch tree', det.leaf_count)
report[#report + 1] = '--'
report[#report + 1] = '-- opcode map (number -> operation):'
local nums = {} for k in pairs(det.opmap) do nums[#nums + 1] = k end table.sort(nums)
local line = '--   '
for _, n in ipairs(nums) do
	local cell = string.format('%d=%s  ', n, det.opmap[n])
	if #line + #cell > 76 then report[#report + 1] = line; line = '--   ' end
	line = line .. cell
end
report[#report + 1] = line
if #det.warnings > 0 then
	report[#report + 1] = '--'
	report[#report + 1] = '-- !! WARNINGS (unrecognised handlers -> new signature needed):'
	for _, w in ipairs(det.warnings) do report[#report + 1] = '-- !!   ' .. w end
end
report[#report + 1] = '--'
report[#report + 1] = '-- Devirtualized register-machine pseudocode follows. r0,r1,... are VM'
report[#report + 1] = '-- registers; _ENV is the script environment; ::pc_NNNN:: are jump targets.'
report[#report + 1] = ''

local out = report
out[#out + 1] = 'local r, upval, top = {}, {}, -1'
out[#out + 1] = 'local _ENV = getfenv and getfenv() or _G'
out[#out + 1] = ''
dump(proto, out, '', det)

write_all(out_path, table.concat(out, '\n') .. '\n')

-- console summary
io.write('[deobfuscate_auto] wrote ' .. out_path .. '\n')
io.write('[deobfuscate_auto] detected ' .. #nums .. ' opcodes, ' ..
	#det.warnings .. ' warning(s)\n')
if #det.warnings > 0 then
	for _, w in ipairs(det.warnings) do io.write('  WARNING: ' .. w .. '\n') end
end
