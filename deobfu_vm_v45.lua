local src_path = assert(arg and arg[1], 'usage: lua deobfu_vm_v45.lua input.lua [output.lua]')
local out_path = arg and arg[2] or (src_path:gsub('%.lua$', '') .. '.v45.deobfuscated.lua')

local function read_all(path)
	local fh = assert(io.open(path, 'rb'), 'failed to open ' .. path)
	local data = fh:read('*a')
	fh:close()
	return data
end

local function write_all(path, data)
	local fh = assert(io.open(path, 'wb'), 'failed to write ' .. path)
	fh:write(data)
	fh:close()
end

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

local function clone(t)
	local out = {}
	for k, v in pairs(t) do
		out[k] = v
	end
	return out
end

local function unescape_string(s)
	return (s:gsub('\127(.)', function(ch)
		return escape_map[ch]
	end))
end

local function base93num(value)
	local out = 0
	for i = 1, #value do
		out = out + 93 ^ (i - 1) * alphabet[value:sub(-i, -i)]
	end
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

local function install_split()
	if not string.split then
		function string:split(sep)
			local out, start = {}, 1
			while true do
				local pos = self:find(sep, start, true)
				if not pos then
					out[#out + 1] = self:sub(start)
					break
				end
				out[#out + 1] = self:sub(start, pos - 1)
				start = pos + #sep
			end
			return out
		end
	end
end

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
				out[#out + 1] = string.char(tonumber(digits))
				pos = pos + #digits + 1
			elseif next_ch == 'n' then
				out[#out + 1] = '\n'
				pos = pos + 2
			elseif next_ch == 'r' then
				out[#out + 1] = '\r'
				pos = pos + 2
			elseif next_ch == 't' then
				out[#out + 1] = '\t'
				pos = pos + 2
			else
				out[#out + 1] = next_ch
				pos = pos + 2
			end
		else
			out[#out + 1] = ch
			pos = pos + 1
		end
	end
	error('unterminated Lua string')
end

local function find_matching(src, start_pos, open_ch, close_ch)
	local depth, quote, pos = 0, nil, start_pos
	while pos <= #src do
		local ch = src:sub(pos, pos)
		if quote then
			if ch == '\\' then
				pos = pos + 2
			elseif ch == quote then
				quote = nil
				pos = pos + 1
			else
				pos = pos + 1
			end
		else
			if ch == '"' or ch == "'" then
				quote = ch
			elseif ch == open_ch then
				depth = depth + 1
			elseif ch == close_ch then
				depth = depth - 1
				if depth == 0 then
					return pos
				end
			end
			pos = pos + 1
		end
	end
	error('unterminated ' .. open_ch)
end

local function decode_hex_pairs(s)
	return (s:gsub('..', function(pair)
		local a, b = pair:byte(1, 2)
		return string.char((a - 65) * 16 + b - 66)
	end))
end

local function extract_constant_blob(src)
	local best, best_name = '', 'blob'
	local start = 1
	while true do
		local assign_start, quote_pos, name = src:find('local%s+([%w_]+)%s*=%s*g%s*%(%s*"', start)
		if not assign_start then
			break
		end
		local payload, quote_end = read_lua_string(src, quote_pos)
		local ok, decoded = pcall(function()
			return decode_hex_pairs(decompress(payload))
		end)
		if ok and #decoded > #best then
			best, best_name = decoded, name
		end
		start = quote_end + 1
	end
	assert(#best > 0, 'constant blob was not found')
	return best, best_name
end

local function extract_entry_proto_expr(src)
	local search_pos, best = 1
	while true do
		local ret_start, call_end = src:find('return%s+[%w_]+%s*%(', search_pos)
		if not ret_start then
			break
		end
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
	if a and b and c then
		return a, b, c
	end
	return 'X', 'C', 'U'
end

local op_names = {
	[0] = 'LT',
	[1] = 'TAILCALL_RETURN',
	[2] = 'UNM',
	[3] = 'FORLOOP',
	[4] = 'LOADBOOL',
	[5] = 'DIV',
	[6] = 'LEN',
	[7] = 'EQ',
	[8] = 'ADD',
	[9] = 'MOD',
	[10] = 'JMP',
	[11] = 'SETLIST',
	[12] = 'GETGLOBAL',
	[13] = 'SETTABLE',
	[14] = 'NOT',
	[15] = 'CLOSE',
	[16] = 'TEST',
	[17] = 'RETURN',
	[18] = 'LE',
	[19] = 'FORPREP',
	[20] = 'SETGLOBAL',
	[21] = 'SUB',
	[22] = 'CLOSURE',
	[23] = 'SELF',
	[24] = 'VARARG',
	[25] = 'MUL',
	[26] = 'GETTABLE',
	[27] = 'TFORLOOP',
	[28] = 'SETUPVAL',
	[29] = 'POW',
	[30] = 'MOVE',
	[31] = 'CALL',
	[32] = 'TESTSET',
	[33] = 'NEWTABLE',
	[34] = 'CONCAT',
	[35] = 'LOADK',
	[36] = 'LOADNIL',
	[37] = 'GETUPVAL',
}

local function decode_instruction_table(raw_proto, const, delim1, delim2, delim3)
	local decoded = decompress(raw_proto)
	local instructions = {}
	for group_index, group in ipairs(decoded:split(delim1)) do
		local inst = {}
		for _, pair in ipairs(group:split(delim2)) do
			local key, value = unpack(pair:split(delim3))
			if key and value and key ~= '' then
				inst[const[key]] = const[value]
			end
		end
		instructions[group_index] = {
			raw = inst,
			is_KB = inst[1],
			has_setlist_extra = inst[2],
			sBx = inst[3],
			is_KC = inst[4],
			C = inst[5],
			B = inst[6],
			const_C = inst[7],
			A = inst[8],
			const_A_or_global = inst[9],
			Bx = inst[10],
			const_B = inst[11],
			op = inst[12],
			opname = op_names[inst[12]] or ('OP_' .. tostring(inst[12])),
		}
	end
	return instructions
end

local function decode_proto(proto, delim1, delim2, delim3)
	local decoded = {
		raw = proto,
		params = proto[3],
		constants = proto[2],
		subprotos = proto[4] or {},
		upvalues = proto[5],
	}
	decoded.instructions = decode_instruction_table(proto[1], proto[2], delim1, delim2, delim3)
	for i, sub in ipairs(decoded.subprotos) do
		decoded.subprotos[i] = decode_proto(sub, delim1, delim2, delim3)
	end
	return decoded
end

local function q(v)
	if type(v) == 'string' then
		return string.format('%q', v)
	end
	return tostring(v)
end

local function raw_table(t)
	local parts = {}
	for k, v in pairs(t) do
		parts[#parts + 1] = '[' .. q(k) .. ']=' .. q(v)
	end
	table.sort(parts)
	return '{' .. table.concat(parts, ', ') .. '}'
end

local function reg(n)
	return 'r' .. tostring(n)
end

local function rk_b(inst)
	if inst.is_KB then
		return q(inst.const_B)
	end
	return reg(inst.B)
end

local function rk_c(inst)
	if inst.is_KC then
		return q(inst.const_C)
	end
	return reg(inst.C)
end

local function regs(start_index, count)
	local out = {}
	for i = 0, count - 1 do
		out[#out + 1] = reg(start_index + i)
	end
	return table.concat(out, ', ')
end

local function call_args(base, encoded_count)
	if encoded_count == 0 then
		return 'unpack(r, ' .. tostring(base + 1) .. ', top)'
	end
	return 'unpack(r, ' .. tostring(base + 1) .. ', ' .. tostring(base + encoded_count - 1) .. ')'
end

local function line_for(inst, pc)
	local op, A, B, C = inst.op, inst.A, inst.B, inst.C
	if op == 0 then
		return 'if (' .. rk_b(inst) .. ' < ' .. rk_c(inst) .. ') ~= ' .. tostring(A ~= 0) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 1 then
		return 'return ' .. reg(A) .. '(' .. call_args(A, B) .. ')'
	elseif op == 2 then
		return reg(A) .. ' = -' .. reg(B)
	elseif op == 3 then
		return '-- FORLOOP base=' .. tostring(A) .. ' jump=' .. tostring(inst.sBx)
	elseif op == 4 then
		return reg(A) .. ' = ' .. tostring(B ~= 0) .. (C ~= 0 and '; goto pc_' .. string.format('%04d', pc + 2) or '')
	elseif op == 5 then
		return reg(A) .. ' = ' .. rk_b(inst) .. ' / ' .. rk_c(inst)
	elseif op == 6 then
		return reg(A) .. ' = #' .. reg(B)
	elseif op == 7 then
		return 'if (' .. rk_b(inst) .. ' == ' .. rk_c(inst) .. ') ~= ' .. tostring(A ~= 0) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 8 then
		return reg(A) .. ' = ' .. rk_b(inst) .. ' + ' .. rk_c(inst)
	elseif op == 9 then
		return reg(A) .. ' = ' .. rk_b(inst) .. ' % ' .. rk_c(inst)
	elseif op == 10 then
		return 'goto pc_' .. string.format('%04d', pc + 1 + (inst.sBx or 0))
	elseif op == 11 then
		return '-- SETLIST table=' .. reg(A) .. ' count=' .. tostring(B) .. ' block=' .. tostring(C)
	elseif op == 12 then
		return reg(A) .. ' = _ENV[' .. q(inst.const_A_or_global) .. ']'
	elseif op == 13 then
		return reg(A) .. '[' .. rk_b(inst) .. '] = ' .. rk_c(inst)
	elseif op == 14 then
		return reg(A) .. ' = not ' .. reg(B)
	elseif op == 15 then
		return '-- CLOSE upvalues >= ' .. tostring(A)
	elseif op == 16 then
		return 'if (not ' .. reg(A) .. ') == ' .. tostring(C ~= 0) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 17 then
		if B == 0 then
			return 'return unpack(r, ' .. tostring(A) .. ', top)'
		end
		return 'return ' .. regs(A, B - 1)
	elseif op == 18 then
		return 'if (' .. rk_b(inst) .. ' <= ' .. rk_c(inst) .. ') ~= ' .. tostring(A ~= 0) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 19 then
		return '-- FORPREP base=' .. tostring(A) .. ' jump=' .. tostring(inst.sBx)
	elseif op == 20 then
		return '_ENV[' .. q(inst.const_A_or_global) .. '] = ' .. reg(A)
	elseif op == 21 then
		return reg(A) .. ' = ' .. rk_b(inst) .. ' - ' .. rk_c(inst)
	elseif op == 22 then
		return reg(A) .. ' = function(...) --[[ subproto ' .. tostring(inst.Bx) .. ' ]] end'
	elseif op == 23 then
		return reg(A) .. ' = ' .. reg(B) .. '[' .. rk_c(inst) .. ']; ' .. reg(A + 1) .. ' = ' .. reg(B)
	elseif op == 24 then
		return '-- VARARG base=' .. tostring(A) .. ' count=' .. tostring(B)
	elseif op == 25 then
		return reg(A) .. ' = ' .. rk_b(inst) .. ' * ' .. rk_c(inst)
	elseif op == 26 then
		return reg(A) .. ' = ' .. reg(B) .. '[' .. rk_c(inst) .. ']'
	elseif op == 27 then
		return '-- TFORLOOP base=' .. tostring(A) .. ' count=' .. tostring(C)
	elseif op == 28 then
		return 'upvalue[' .. tostring(B) .. '] = ' .. reg(A)
	elseif op == 29 then
		return reg(A) .. ' = ' .. rk_b(inst) .. ' ^ ' .. rk_c(inst)
	elseif op == 30 then
		return reg(A) .. ' = ' .. reg(B)
	elseif op == 31 then
		if C == 0 then
			return reg(A) .. ', top = ' .. reg(A) .. '(' .. call_args(A, B) .. ')'
		elseif C == 1 then
			return reg(A) .. '(' .. call_args(A, B) .. ')'
		end
		return regs(A, C - 1) .. ' = ' .. reg(A) .. '(' .. call_args(A, B) .. ')'
	elseif op == 32 then
		return 'if (' .. reg(B) .. ') == ' .. tostring(C ~= 0) .. ' then ' .. reg(A) .. ' = ' .. reg(B) .. ' else goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 33 then
		return reg(A) .. ' = {}'
	elseif op == 34 then
		return reg(A) .. ' = table.concat({unpack(r, ' .. tostring(B) .. ', ' .. tostring(C) .. ')})'
	elseif op == 35 then
		return reg(A) .. ' = ' .. q(inst.const_A_or_global)
	elseif op == 36 then
		return 'for i = ' .. tostring(A) .. ', ' .. tostring(B) .. ' do r[i] = nil end'
	elseif op == 37 then
		return reg(A) .. ' = upvalue[' .. tostring(B) .. ']'
	end
	return '-- ' .. raw_table(inst.raw)
end

local function dump_proto(proto, out, indent, name)
	indent = indent or ''
	name = name or 'main'
	out[#out + 1] = indent .. '-- function ' .. name .. ' params=' .. tostring(proto.params) .. ' upvalues=' .. tostring(proto.upvalues) ..
		' instructions=' .. tostring(#proto.instructions) .. ' subprotos=' .. tostring(#proto.subprotos)
	out[#out + 1] = indent .. 'do'
	for pc, inst in ipairs(proto.instructions) do
		out[#out + 1] = indent .. '\t::pc_' .. string.format('%04d', pc) .. ':: -- ' .. inst.opname .. ' ' .. raw_table(inst.raw)
		out[#out + 1] = indent .. '\t' .. line_for(inst, pc)
	end
	out[#out + 1] = indent .. 'end'
	for i, sub in ipairs(proto.subprotos) do
		out[#out + 1] = ''
		dump_proto(sub, out, indent, name .. '_sub' .. tostring(i))
	end
end

install_split()

local src = read_all(src_path)
local constant_blob, blob_name = extract_constant_blob(src)
local delim1, delim2, delim3 = detect_delimiters(src)
local proto_expr = extract_entry_proto_expr(src)
local substr = function(...)
	return constant_blob:sub(...)
end
local env = setmetatable({
	[blob_name] = substr,
	b = substr,
	a = substr,
	_1 = substr,
	['true'] = true,
	['false'] = false,
}, {
	__index = function(_, key)
		if type(key) == 'string' and #key <= 3 then
			return substr
		end
		return _G[key]
	end,
})
local proto_loader = assert(loadstring('return ' .. proto_expr))
setfenv(proto_loader, env)
local proto = decode_proto(proto_loader(), delim1, delim2, delim3)

local out = {
	'-- OBFUv4.5 decoded output from ' .. src_path,
	'-- Constants were decoded from the first packed string and VM fields were rebound to canonical names.',
	'-- Delimiters: instruction=' .. q(delim1) .. ' pair=' .. q(delim2) .. ' keyvalue=' .. q(delim3),
	'-- Constant blob bytes: ' .. tostring(#constant_blob),
	'',
	'local _ENV = getfenv and getfenv() or _G',
	'local r, upvalue, top = {}, {}, -1',
	'',
}

dump_proto(proto, out)
write_all(out_path, table.concat(out, '\n') .. '\n')
print('Wrote OBFUv4.5 decoded listing to ' .. out_path)
