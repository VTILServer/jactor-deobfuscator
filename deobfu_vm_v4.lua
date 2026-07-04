local src_path = arg and arg[1] or 'input.obfuv3.lua'
local out_path = arg and arg[2] or 'input.obfuv3.deobfuscated.lua'

local function read_all(path)
	local fh = assert(io.open(path, 'rb'))
	local data = fh:read('*a')
	fh:close()
	return data
end

local function write_all(path, data)
	local fh = assert(io.open(path, 'wb'))
	fh:write(data)
	fh:close()
end

local f, n = {}, 0
for i = 32, 127 do
	if i ~= 34 and i ~= 92 then
		local ch = string.char(i)
		f[ch], f[n] = n, ch
		n = n + 1
	end
end

local escape_map = {}
for i = 1, 34 do
	local code = ({34, 92, 127})[i - 31] or i
	local a, b = string.char(code), string.char(code + 31)
	escape_map[a], escape_map[b] = b, a
end

local function unescape(s)
	return s:gsub('\127(.)', function(ch)
		return escape_map[ch]
	end)
end

local function clone(t)
	local out = {}
	for k, v in pairs(t) do out[k] = v end
	return out
end

local function base93num(value)
	local out = 0
	for i = 1, #value do
		out = out + 93 ^ (i - 1) * f[value:sub(-i, -i)]
	end
	return out
end

local function decompress(text)
	local dict = clone(f)
	local output, spans, content = {}, text:match('(.-)|(.*)')
	assert(spans and content, 'compressed stream is malformed')

	local groups, pos = {}, 1
	for span in spans:gmatch('%d+') do
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

	return unescape(table.concat(output))
end

local function install_split()
	if not string.split then
		function string:split(sep)
			local out = {}
			local start = 1
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

local function find_matching_brace(src, brace_start)
	local depth, quote, pos = 0, nil, brace_start

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
			elseif ch == '{' then
				depth = depth + 1
			elseif ch == '}' then
				depth = depth - 1
				if depth == 0 then
					return pos
				end
			end
			pos = pos + 1
		end
	end

	error('unterminated VM prototype table')
end

local function extract_main_proto_expr(src)
	local search_pos = 1
	local best_expr

	while true do
		local start, call_end = src:find('return%s+[%w_]+%s*%(', search_pos)
		if not start then
			break
		end

		local brace_start = src:find('{', call_end + 1, true)
		if brace_start then
			local ok, brace_end = pcall(find_matching_brace, src, brace_start)
			if ok then
				local suffix = src:sub(brace_end + 1, brace_end + 64)
				if suffix:match('^%s*,%s*[%w_]+%s*%(%s*%)%s*%)%s*%(%s*%)') then
					best_expr = src:sub(brace_start, brace_end)
				end
			end
		end

		search_pos = call_end + 1
	end

	assert(best_expr, 'VM entry return <func>({...}, getfenv())() not found')
	return best_expr
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

local function decode_hex_pairs(s)
	return (s:gsub('..', function(pair)
		local a, b = pair:byte(1, 2)
		return string.char((a - 65) * 16 + b - 66)
	end))
end

local function extract_constant_blob(src)
	local best = ''
	local start = 1
	while true do
		local call_start, quote_pos = src:find('[%w_]+%s*%(%s*"', start)
		if not call_start then break end
		local payload = read_lua_string(src, quote_pos)
		local ok, decoded = pcall(function()
			return decode_hex_pairs(decompress(payload))
		end)
		if ok and decoded:find('script', 1, true) and decoded:find('game', 1, true) then
			return decoded
		elseif ok and #decoded > #best then
			best = decoded
		end
		start = quote_pos + #payload + 2
	end
	return best
end

local function decode_proto(proto)
	local raw_subprotos = proto[1]
	local raw_code = proto[2]
	local raw_upvalues = proto[3]
	local const = proto[4]
	local raw_params = proto[5]
	local decoded = decompress(raw_code)
	local instructions = {}

	for group_index, group in ipairs(decoded:split('P')) do
		local inst = {}
		for _, pair in ipairs(group:split('I')) do
			local key, value = unpack(pair:split('K'))
			if key and value and key ~= '' then
				inst[const[key]] = const[value]
			end
		end
		instructions[group_index] = inst
	end

	return {
		raw_params,
		raw_upvalues,
		raw_subprotos,
		instructions,
	}
end

local op_names = {
	[0] = 'DIV',
	[1] = 'LOADNIL',
	[2] = 'TFORLOOP',
	[3] = 'LOADK',
	[4] = 'SETUPVAL',
	[5] = 'JMP',
	[6] = 'POW',
	[7] = 'NOT',
	[8] = 'UNM',
	[9] = 'MUL',
	[10] = 'LEN',
	[11] = 'MOVE',
	[12] = 'LOADBOOL',
	[13] = 'CLOSE',
	[14] = 'CLOSURE',
	[15] = 'SETGLOBAL',
	[16] = 'CALL',
	[17] = 'CONCAT',
	[18] = 'LE',
	[19] = 'LT',
	[20] = 'FORPREP',
	[21] = 'SUB',
	[22] = 'RETURN',
	[23] = 'SELF',
	[24] = 'SETLIST',
	[25] = 'GETUPVAL',
	[26] = 'EQ',
	[27] = 'VARARG',
	[28] = 'SETTABLE',
	[29] = 'ADD',
	[30] = 'TEST',
	[31] = 'TAILCALL',
	[32] = 'GETGLOBAL',
	[33] = 'MOD',
	[34] = 'NEWTABLE',
	[35] = 'GETTABLE',
	[36] = 'TESTSET',
	[37] = 'FORLOOP',
}
op_names = {
	[0] = 'LOADK',
	[12] = 'JMP',
	[15] = 'SETLIST',
	[24] = 'NEWTABLE',
	[31] = 'LOADBOOL',
	[36] = 'GETTABLEK',
	[39] = 'GETGLOBAL',
	[41] = 'FORLOOP',
	[42] = 'CALL',
	[52] = 'MOVE',
	[55] = 'SELF',
	[62] = 'CLOSURE',
}

local function format_value(v)
	if type(v) == 'string' then
		return string.format('%q', v)
	end
	return tostring(v)
end

local function rk(inst, reg_field, const_flag, const_field)
	if inst[const_flag] then
		return 'K(' .. format_value(inst[const_field]) .. ')'
	end
	return 'R' .. tostring(inst[reg_field])
end

local function describe(inst)
	return 'raw=' .. format_value_table(inst)
end

local function describe_v3_unused(inst)
	local op = inst[4]
	local A, B, C = inst[9], inst[8], inst[6]
	if op == 32 then
		return string.format('R%s = ENV[%s]', tostring(A), format_value(inst[4]))
	elseif op == 15 then
		return string.format('ENV[%s] = R%s', format_value(inst[4]), tostring(A))
	elseif op == 13 then
		return string.format('CLOSE R%s+', tostring(A))
	elseif op == 11 then
		return string.format('R%s = R%s', tostring(A), tostring(B))
	elseif op == 35 then
		return string.format('R%s = R%s[%s]', tostring(A), tostring(B), rk(inst, 6, 10, 1))
	elseif op == 28 then
		return string.format('R%s[%s] = %s', tostring(A), rk(inst, 8, 11, 5), rk(inst, 6, 10, 1))
	elseif op == 29 or op == 21 or op == 9 or op == 0 or op == 33 or op == 6 then
		local symbol = ({[29] = '+', [21] = '-', [9] = '*', [0] = '/', [33] = '%', [6] = '^'})[op]
		return string.format('R%s = %s %s %s', tostring(A), rk(inst, 8, 11, 5), symbol, rk(inst, 6, 10, 1))
	elseif op == 16 then
		return string.format('CALL R%s args=%s returns=%s', tostring(A), tostring(B and (B - 1) or '?'), tostring(C and (C - 1) or '?'))
	elseif op == 22 then
		return string.format('RETURN R%s count=%s', tostring(A), tostring(B and (B - 1) or 'var'))
	elseif op == 31 then
		return string.format('TAILCALL R%s args=%s', tostring(A), tostring(B and (B - 1) or '?'))
	elseif op == 5 then
		return string.format('JMP %+d', inst[2] or 0)
	elseif op == 26 or op == 19 or op == 18 then
		local symbol = ({[26] = '==', [19] = '<', [18] = '<='})[op]
		return string.format('IF (%s %s %s) ~= %s THEN skip', rk(inst, 8, 11, 5), symbol, rk(inst, 6, 10, 1), tostring(A ~= 0))
	elseif op == 34 then
		return string.format('R%s = {}', tostring(A))
	elseif op == 12 then
		return string.format('R%s = %s; skip_if=%s', tostring(A), tostring(B ~= 0), tostring(C ~= 0))
	elseif op == 14 then
		return string.format('R%s = CLOSURE proto=%s', tostring(A), tostring(inst[7]))
	elseif op == 23 then
		return string.format('R%s = R%s[%s]; R%s = R%s', tostring(A), tostring(B), rk(inst, 6, 10, 1), tostring(A + 1), tostring(B))
	elseif op == 3 then
		return string.format('R%s = %s', tostring(A), format_value(inst[4]))
	end
	return 'raw=' .. format_value_table(inst)
end

function format_value_table(t)
	local parts = {}
	for k, v in pairs(t) do
		parts[#parts + 1] = tostring(k) .. '=' .. format_value(v)
	end
	table.sort(parts)
	return '{' .. table.concat(parts, ', ') .. '}'
end

local function reg(index)
	return 'r' .. tostring(index)
end

local function register_list(start_index, count)
	local parts = {}
	for index = start_index, start_index + count - 1 do
		parts[#parts + 1] = reg(index)
	end
	return table.concat(parts, ', ')
end

local function call_arguments(base, encoded_count)
	if encoded_count == 0 then
		return register_list(base + 1, 3) .. ', ...'
	end
	return register_list(base + 1, math.max(encoded_count - 1, 0))
end

local function expr_rk(inst, reg_field, const_flag, const_field)
	if inst[const_flag] then
		return format_value(inst[const_field])
	end
	return reg(inst[reg_field])
end

local function emit_lua_like(proto, out, indent)
	indent = indent or ''
	out[#out + 1] = indent .. string.format('-- function params=%s upvalues=%s', tostring(proto[1]), tostring(proto[2]))
	out[#out + 1] = indent .. 'do'

	local body_indent = indent .. '\t'
	for pc, inst in ipairs(proto[4]) do
		local op = inst[4]
		local line
		local A, B, C = inst[9], inst[8], inst[6]

		if op == 3 then
			line = string.format('%s = %s', reg(A), format_value(inst[4]))
		elseif op == 32 then
			line = string.format('%s = _ENV[%s]', reg(A), format_value(inst[4]))
		elseif op == 15 then
			line = string.format('_ENV[%s] = %s', format_value(inst[4]), reg(A))
		elseif op == 13 then
			line = string.format('-- CLOSE %s+', reg(A))
		elseif op == 11 then
			line = string.format('%s = %s', reg(A), reg(B))
		elseif op == 1 then
			line = string.format('for i = %s, %s do r[i] = nil end', tostring(A), tostring(B))
		elseif op == 12 then
			line = string.format('%s = %s', reg(A), tostring(B ~= 0))
		elseif op == 34 then
			line = string.format('%s = {}', reg(A))
		elseif op == 35 then
			line = string.format('%s = %s[%s]', reg(A), reg(B), expr_rk(inst, 6, 10, 1))
		elseif op == 28 then
			line = string.format('%s[%s] = %s', reg(A), expr_rk(inst, 8, 11, 5), expr_rk(inst, 6, 10, 1))
		elseif op == 23 then
			line = string.format('%s = %s[%s]; %s = %s', reg(A), reg(B), expr_rk(inst, 6, 10, 1), reg(A + 1), reg(B))
		elseif op == 29 or op == 21 or op == 9 or op == 0 or op == 33 or op == 6 then
			local symbol = ({[29] = '+', [21] = '-', [9] = '*', [0] = '/', [33] = '%', [6] = '^'})[op]
			line = string.format('%s = %s %s %s', reg(A), expr_rk(inst, 8, 11, 5), symbol, expr_rk(inst, 6, 10, 1))
		elseif op == 8 then
			line = string.format('%s = -%s', reg(A), reg(B))
		elseif op == 7 then
			line = string.format('%s = not %s', reg(A), reg(B))
		elseif op == 10 then
			line = string.format('%s = #%s', reg(A), reg(B))
		elseif op == 17 then
			line = string.format('%s = table.concat({%s..%s}) -- CONCAT range', reg(A), reg(B), reg(C))
		elseif op == 16 then
			local call = string.format('%s(%s)', reg(A), call_arguments(A, B))
			if C == 0 then
				line = string.format('%s, ... = %s -- CALL variable returns', reg(A), call)
			elseif C == 1 then
				line = call
			else
				line = string.format('%s = %s', register_list(A, C - 1), call)
			end
		elseif op == 31 then
			line = string.format('return %s(%s) -- TAILCALL', reg(A), call_arguments(A, B))
		elseif op == 22 then
			if B == 0 then
				line = string.format('return %s, ... -- variable return count', reg(A))
			elseif B == 1 then
				line = 'return'
			else
				line = string.format('return %s', register_list(A, B - 1))
			end
		elseif op == 5 then
			line = string.format('goto pc_%04d -- JMP %+d', pc + 1 + (inst[2] or 0), inst[2] or 0)
		elseif op == 26 or op == 19 or op == 18 then
			local symbol = ({[26] = '==', [19] = '<', [18] = '<='})[op]
			line = string.format('if (%s %s %s) ~= %s then goto pc_%04d end',
				expr_rk(inst, 8, 11, 5), symbol, expr_rk(inst, 6, 10, 1), tostring(A ~= 0), pc + 2)
		elseif op == 30 then
			line = string.format('if (not %s) == %s then goto pc_%04d end', reg(A), tostring(C ~= 0), pc + 2)
		elseif op == 36 then
			line = string.format('if (%s) == %s then %s = %s else goto pc_%04d end', reg(B), tostring(C ~= 0), reg(A), reg(B), pc + 2)
		elseif op == 14 then
			line = string.format('%s = function(...) --[[ subproto %s ]] end', reg(A), tostring(inst[7]))
		elseif op == 27 then
			line = string.format('-- VARARG into %s count=%s', reg(A), tostring(B))
		elseif op == 24 then
			line = string.format('-- SETLIST table=%s count=%s block=%s', reg(A), tostring(B), tostring(C))
		elseif op == 20 then
			line = string.format('-- FORPREP base=%s jump=%s', reg(A), tostring(inst[2]))
		elseif op == 37 then
			line = string.format('-- FORLOOP base=%s jump=%s', reg(A), tostring(inst[2]))
		elseif op == 2 then
			line = string.format('-- TFORLOOP base=%s count=%s', reg(A), tostring(C))
		else
			line = '-- ' .. describe(inst)
		end

		out[#out + 1] = body_indent .. string.format('::pc_%04d:: %s', pc, line)
	end

	out[#out + 1] = indent .. 'end'

	for index, sub in ipairs(proto[3] or {}) do
		out[#out + 1] = ''
		out[#out + 1] = indent .. string.format('-- subproto %d', index)
		emit_lua_like(decode_proto(sub), out, indent)
	end
end

local function dump_proto(proto, out, indent)
	indent = indent or ''
	out[#out + 1] = indent .. string.format('-- params=%s upvalues=%s instructions=%d subprotos=%d',
		tostring(proto[1]), tostring(proto[2]), #proto[4], #(proto[3] or {}))

	for pc, inst in ipairs(proto[4]) do
		local op = inst[4]
		out[#out + 1] = indent .. string.format('%04d %-10s %s', pc, op_names[op] or ('OP_' .. tostring(op)), describe(inst))
	end

	for index, sub in ipairs(proto[3] or {}) do
		out[#out + 1] = ''
		out[#out + 1] = indent .. string.format('-- subproto %d', index)
		dump_proto(decode_proto(sub), out, indent .. '  ')
	end
end

local function raw_table(t)
	local parts = {}
	for k, v in pairs(t) do
		parts[#parts + 1] = '[' .. format_value(k) .. ']=' .. format_value(v)
	end
	table.sort(parts)
	return '{' .. table.concat(parts, ',') .. '}'
end

local function v4_reg(index)
	return 'r' .. tostring(index)
end

local function v4_value(value)
	if type(value) == 'string' then
		return string.format('%q', value)
	end
	return tostring(value)
end

local function v4_unpack_args(base, count)
	if count == nil then
		return 'unpack(r, ' .. tostring(base + 1) .. ', top)'
	end
	return 'unpack(r, ' .. tostring(base + 1) .. ', ' .. tostring(base + count) .. ')'
end

local function v4_results(base, count, call)
	if count == nil then
		return v4_reg(base) .. ', top = packresults(' .. call .. ')'
	end
	if count == 0 then
		return call
	end
	local regs = {}
	for i = 0, count - 1 do
		regs[#regs + 1] = v4_reg(base + i)
	end
	return table.concat(regs, ', ') .. ' = ' .. call
end

local function v4_rk_reg_or_const(inst, reg_field, const_field)
	if inst[const_field] ~= nil and inst[reg_field] == nil then
		return v4_value(inst[const_field])
	end
	return v4_reg(inst[reg_field])
end

local function v4_line(item)
	local inst, pc = item.inst, item.pc
	local op, A, B, C = inst[4], inst[5], inst[10], inst[8]

	if op == 0 then
		return v4_reg(A) .. ' = ' .. v4_value(B)
	elseif op == 3 then
		return v4_reg(C) .. '[' .. v4_reg(A) .. '] = ' .. v4_value(B)
	elseif op == 4 then
		return 'setUpvalue(upvalues, ' .. tostring(A) .. ', ' .. v4_reg(B) .. ')'
	elseif op == 5 then
		return 'for i = 1, ' .. tostring(B) .. ' do ' .. v4_reg(A) .. '[i] = varargs[i] end'
	elseif op == 6 then
		return v4_reg(C) .. '[' .. v4_reg(A) .. '] = ' .. v4_reg(B)
	elseif op == 7 then
		return v4_reg(A) .. ' = getUpvalue(upvalues, ' .. tostring(B) .. ')'
	elseif op == 8 then
		return 'if (' .. v4_value(A) .. ' == ' .. v4_reg(B) .. ') ~= ' .. tostring(C) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 10 then
		return 'env[' .. v4_value(A) .. '] = ' .. v4_reg(B)
	elseif op == 11 then
		return v4_reg(C) .. ' = ' .. v4_reg(A) .. ' + ' .. v4_reg(B)
	elseif op == 12 then
		return 'goto pc_' .. string.format('%04d', pc + 1 + A) .. ' -- jump ' .. tostring(A)
	elseif op == 13 then
		return '-- TFORLOOP base=' .. tostring(A) .. ' count=' .. tostring(C)
	elseif op == 14 then
		return '-- SETLIST ' .. v4_reg(A) .. ' count=' .. tostring(C) .. ' block=' .. tostring(B)
	elseif op == 15 then
		return v4_reg(C) .. ' = ' .. v4_reg(A) .. ' + ' .. v4_value(B)
	elseif op == 16 then
		return 'if (' .. v4_reg(A) .. ' <= ' .. v4_reg(B) .. ') ~= ' .. tostring(C) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 17 then
		return 'if (not ' .. v4_reg(B) .. ') == ' .. tostring(C) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' else ' .. v4_reg(A) .. ' = ' .. v4_reg(B) .. ' end'
	elseif op == 18 then
		return v4_results(A, nil, v4_reg(A) .. '(' .. v4_unpack_args(A) .. ')')
	elseif op == 19 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' - ' .. v4_reg(B)
	elseif op == 20 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' ^ ' .. v4_value(B)
	elseif op == 21 then
		return 'return ' .. v4_reg(A) .. '(' .. v4_unpack_args(A, B) .. ')'
	elseif op == 22 then
		return v4_reg(C) .. ' = table.concat({unpack(r, ' .. tostring(A) .. ', ' .. tostring(B) .. ')})'
	elseif op == 24 then
		return v4_reg(A) .. ' = {}'
	elseif op == 25 then
		return 'for i = ' .. tostring(A) .. ', ' .. tostring(B) .. ' do r[i] = nil end'
	elseif op == 26 then
		return v4_reg(C) .. ' = ' .. v4_reg(A) .. ' * ' .. v4_value(B)
	elseif op == 27 then
		return v4_reg(B) .. ' = ' .. v4_reg(C) .. '[' .. v4_reg(A) .. ']'
	elseif op == 28 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' + ' .. v4_value(B)
	elseif op == 29 then
		return 'return unpack(r, ' .. tostring(A) .. ', top)'
	elseif op == 30 then
		return v4_reg(C) .. ' = ' .. v4_reg(A) .. ' - ' .. v4_value(B)
	elseif op == 31 then
		return v4_reg(A) .. ' = ' .. tostring(B) .. (C and '; goto pc_' .. string.format('%04d', pc + 2) or '')
	elseif op == 32 then
		return v4_reg(C) .. ' = ' .. v4_reg(A) .. ' ^ ' .. v4_reg(B)
	elseif op == 33 then
		return v4_reg(A) .. ' = not ' .. v4_reg(B)
	elseif op == 34 then
		return v4_reg(C) .. '[' .. v4_value(A) .. '] = ' .. v4_reg(B)
	elseif op == 35 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' ^ ' .. v4_reg(B)
	elseif op == 36 then
		return v4_reg(B) .. ' = ' .. v4_reg(C) .. '[' .. v4_value(A) .. ']'
	elseif op == 37 then
		return v4_reg(B) .. ' = ' .. v4_reg(C) .. '[' .. v4_value(A) .. ']'
	elseif op == 38 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' * ' .. v4_reg(B)
	elseif op == 39 then
		return v4_reg(A) .. ' = env[' .. v4_value(B) .. ']'
	elseif op == 40 or op == 41 then
		return '-- FORLOOP base=' .. tostring(A) .. ' jump=' .. tostring(B)
	elseif op == 42 then
		return v4_results(A, C, v4_reg(A) .. '(' .. v4_unpack_args(A, B) .. ')')
	elseif op == 43 then
		return 'if (not ' .. v4_reg(A) .. ') == ' .. tostring(B) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 44 then
		return v4_reg(C) .. ' = ' .. v4_reg(A) .. ' * ' .. v4_reg(B)
	elseif op == 45 then
		return v4_reg(C) .. ' = ' .. v4_reg(A) .. ' / ' .. v4_value(B)
	elseif op == 46 then
		return 'if (' .. v4_reg(A) .. ' < ' .. v4_reg(B) .. ') ~= ' .. tostring(C) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 47 then
		return v4_reg(C) .. ' = ' .. v4_reg(A) .. ' % ' .. v4_value(B)
	elseif op == 48 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' - ' .. v4_value(B)
	elseif op == 49 then
		return v4_reg(C) .. ' = ' .. v4_reg(A) .. ' / ' .. v4_reg(B)
	elseif op == 50 then
		return v4_results(A, B, v4_reg(A) .. '(' .. v4_unpack_args(A) .. ')')
	elseif op == 51 then
		return '-- VARARG base=' .. tostring(A)
	elseif op == 52 then
		return v4_reg(A) .. ' = ' .. v4_reg(B)
	elseif op == 53 then
		if B == 0 then
			return 'return unpack(r, ' .. tostring(A) .. ', top)'
		end
		local regs = {}
		for i = 0, B - 1 do regs[#regs + 1] = v4_reg(A + i) end
		return 'return ' .. table.concat(regs, ', ')
	elseif op == 54 then
		return v4_reg(C) .. ' = ' .. v4_reg(B) .. ' ^ ' .. v4_value(A)
	elseif op == 55 then
		return v4_reg(A) .. ' = ' .. v4_reg(B) .. '[' .. v4_value(C) .. ']; ' .. v4_reg(A + 1) .. ' = ' .. v4_reg(B)
	elseif op == 56 then
		return 'if (' .. v4_reg(A) .. ' == ' .. v4_value(B) .. ') ~= ' .. tostring(C) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 57 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' % ' .. v4_reg(B)
	elseif op == 58 then
		return '-- CLOSE upvalues >= ' .. tostring(A)
	elseif op == 59 then
		return v4_reg(C or A) .. '[' .. v4_value(A) .. '] = ' .. v4_value(B)
	elseif op == 60 then
		return v4_reg(C) .. '[' .. v4_value(A) .. '] = ' .. v4_value(B)
	elseif op == 61 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' % ' .. v4_value(B)
	elseif op == 62 then
		return v4_reg(A) .. ' = function(...) --[[ subproto ' .. tostring(B) .. ' ]] end'
	elseif op == 63 then
		return '-- SETLIST variable ' .. v4_reg(A) .. ' block=' .. tostring(B)
	elseif op == 64 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' / ' .. v4_reg(B)
	elseif op == 65 then
		return v4_reg(A) .. ' = #' .. v4_reg(B)
	elseif op == 66 then
		return v4_reg(A) .. ' = ' .. v4_reg(B) .. '[' .. v4_reg(C) .. ']; ' .. v4_reg(A + 1) .. ' = ' .. v4_reg(B)
	elseif op == 67 then
		return v4_reg(A) .. ' = -' .. v4_reg(B)
	elseif op == 68 then
		return v4_reg(A) .. ' = -' .. v4_reg(B)
	elseif op == 69 then
		return 'if (' .. v4_reg(A) .. ' <= ' .. v4_value(B) .. ') ~= ' .. tostring(C) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	elseif op == 70 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' * ' .. v4_value(B)
	elseif op == 71 then
		return v4_reg(C) .. ' = ' .. v4_value(A) .. ' / ' .. v4_value(B)
	elseif op == 72 then
		return v4_results(A, nil, v4_reg(A) .. '(' .. v4_unpack_args(A, B) .. ')')
	elseif op == 73 then
		return v4_reg(A) .. ' = #' .. v4_reg(B)
	elseif op == 74 then
		return 'if (' .. v4_value(A) .. ' < ' .. v4_reg(B) .. ') ~= ' .. tostring(C) .. ' then goto pc_' .. string.format('%04d', pc + 2) .. ' end'
	end

	return '-- ' .. raw_table(inst)
end

local function dump_v4_lifted(proto, out, indent)
	indent = indent or ''
	out[#out + 1] = indent .. string.format('-- function params=%s upvalues=%s instructions=%d subprotos=%d',
		tostring(proto[1]), tostring(proto[2]), #proto[4], #(proto[3] or {}))
	out[#out + 1] = indent .. 'do'
	for pc, inst in ipairs(proto[4]) do
		out[#out + 1] = indent .. '\t::pc_' .. string.format('%04d', pc) .. ':: ' .. v4_line({ pc = pc, inst = inst })
	end
	out[#out + 1] = indent .. 'end'

	for index, sub in ipairs(proto[3] or {}) do
		out[#out + 1] = ''
		out[#out + 1] = indent .. '-- subproto ' .. tostring(index)
		dump_v4_lifted(decode_proto(sub), out, indent .. '  ')
	end
end

local function dump_raw_proto(proto, out, indent)
	indent = indent or ''
	out[#out + 1] = indent .. string.format('-- params=%s upvalues=%s instructions=%d subprotos=%d',
		tostring(proto[1]), tostring(proto[2]), #proto[4], #(proto[3] or {}))

	for pc, inst in ipairs(proto[4]) do
		local op = inst[4]
		out[#out + 1] = indent .. string.format('%04d %-10s %s', pc, op_names[op] or ('OP_' .. tostring(op)), raw_table(inst))
	end

	for index, sub in ipairs(proto[3] or {}) do
		out[#out + 1] = ''
		out[#out + 1] = indent .. string.format('-- subproto %d', index)
		dump_raw_proto(decode_proto(sub), out, indent .. '  ')
	end
end

install_split()

local src = read_all(src_path)
local proto_expr = extract_main_proto_expr(src)
local constant_blob = extract_constant_blob(src)
local proto_loader = assert(loadstring('return ' .. proto_expr))
setfenv(proto_loader, {
	a = function(...)
		return constant_blob:sub(...)
	end,
	_1 = function(...)
		return constant_blob:sub(...)
	end,
})
local proto = proto_loader()
proto = decode_proto(proto)

local out = {
	'-- Devirtualized output from ' .. src_path,
	'-- This v4 wrapper stores a custom VM prototype, not a Lua bytecode chunk.',
	'-- The output below decodes the packed VM prototype and instruction tables.',
	'',
}

out[#out + 1] = '-- VM instruction listing:'
dump_proto(proto, out)
out[#out + 1] = ''

out[#out + 1] = '-- Lua-like lifted output:'
dump_v4_lifted(proto, out)
out[#out + 1] = ''

out[#out + 1] = '-- VM raw instruction listing:'
dump_raw_proto(proto, out)

write_all(out_path, table.concat(out, '\n') .. '\n')
print('Wrote VM listing to ' .. out_path)
