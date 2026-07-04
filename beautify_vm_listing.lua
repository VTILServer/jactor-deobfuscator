local src_path = arg and arg[1] or 'input.obfuv3.deobfuscated.lua'
local out_path = arg and arg[2] or src_path:gsub('%.lua$', '.beautified.lua')

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

local function q(value)
	return string.format('%q', value)
end

local function lua_ident(value)
	return type(value) == 'string' and value:match('^[A-Za-z_][A-Za-z0-9_]*$')
end

local function global_expr(name)
	if name == 'script' or name == 'game' or name == 'workspace' or name == 'require' then
		return name
	end
	if lua_ident(name) then
		return 'env.' .. name
	end
	return 'env[' .. q(name) .. ']'
end

local function raw_value(value)
	if type(value) == 'string' then
		return q(value)
	end
	return tostring(value)
end

local function parse_raw_listing(src)
	local raw = src:match('%-%- VM raw instruction listing:%s*\n(.+)')
	assert(raw, 'VM raw instruction listing section not found. Re-run deobfu_vm_v3.lua first.')

	local instructions = {}
	local header
	for line in raw:gmatch('[^\r\n]+') do
		header = header or line:match('%-%- params=.*')
		local pc, op, table_src = line:match('^%s*(%d+)%s+(%S+)%s+({.+})%s*$')
		if pc then
			local loader = assert(loadstring('return ' .. table_src))
			setfenv(loader, {})
			instructions[#instructions + 1] = {
				pc = tonumber(pc),
				op = op,
				inst = loader(),
			}
		end
	end

	assert(#instructions > 0, 'No raw VM instructions found')
	return header or '-- params=? upvalues=? instructions=' .. tostring(#instructions), instructions
end

local function rk(inst, reg_field, const_flag, const_field)
	if inst[const_flag] then
		return raw_value(inst[const_field])
	end
	return 'r[' .. tostring(inst[reg_field]) .. ']'
end

local function arg_expr(base, encoded_count)
	if encoded_count == 0 then
		return 'unpackRegisters(r, ' .. tostring(base + 1) .. ', top)'
	end
	return 'unpackRegisters(r, ' .. tostring(base + 1) .. ', ' .. tostring(base + encoded_count - 1) .. ')'
end

local function result_assignments(base, encoded_count)
	if encoded_count == 0 then
		return {
			'local results = pack(...)',
			'for i = 1, results.n do r[' .. tostring(base) .. ' + i - 1] = results[i] end',
			'top = ' .. tostring(base) .. ' + results.n - 1',
		}
	end

	local lines = {}
	for index = 1, encoded_count - 1 do
		lines[#lines + 1] = 'r[' .. tostring(base + index - 1) .. '] = results[' .. tostring(index) .. ']'
	end
	return lines
end

local function call_lines(inst, tail)
	local A, B, C = inst[9], inst[8], inst[6]
	local call = 'r[' .. tostring(A) .. '](' .. arg_expr(A, B) .. ')'
	if tail then
		return { 'return ' .. call }
	end
	if C == 1 then
		return { call }
	end

	local lines = { 'local results = pack(' .. call .. ')' }
	for _, line in ipairs(result_assignments(A, C)) do
		lines[#lines + 1] = line
	end
	return lines
end

local function return_line(inst)
	local A, B = inst[9], inst[8]
	if B == 0 then
		return 'return unpackRegisters(r, ' .. tostring(A) .. ', top)'
	end
	if B == 1 then
		return 'return'
	end
	return 'return unpackRegisters(r, ' .. tostring(A) .. ', ' .. tostring(A + B - 2) .. ')'
end

local function next_pc_line(pc)
	return 'pc = ' .. tostring(pc + 1)
end

local function instruction_lines(item)
	local inst = item.inst
	local op = inst[3]
	local A, B, C = inst[9], inst[8], inst[6]
	local lines = {}

	if op == 0 then
		lines[#lines + 1] = 'r[' .. A .. '] = ' .. rk(inst, 8, 11, 5) .. ' / ' .. rk(inst, 6, 10, 1)
	elseif op == 1 then
		lines[#lines + 1] = 'for i = ' .. A .. ', ' .. B .. ' do r[i] = nil end'
	elseif op == 2 then
		lines[#lines + 1] = 'local results = pack(r[' .. A .. '](r[' .. (A + 1) .. '], r[' .. (A + 2) .. ']))'
		lines[#lines + 1] = 'for i = 1, ' .. C .. ' do r[' .. (A + 2) .. ' + i] = results[i] end'
		lines[#lines + 1] = 'if r[' .. (A + 3) .. '] ~= nil then r[' .. (A + 2) .. '] = r[' .. (A + 3) .. '] else pc = pc + 1 end'
	elseif op == 3 then
		lines[#lines + 1] = 'r[' .. A .. '] = ' .. raw_value(inst[4])
	elseif op == 4 then
		lines[#lines + 1] = 'setUpvalue(upvalues, ' .. tostring(B) .. ', r[' .. A .. '])'
	elseif op == 5 then
		lines[#lines + 1] = 'pc = pc + ' .. tostring(inst[2] or 0)
		return lines
	elseif op == 6 then
		lines[#lines + 1] = 'r[' .. A .. '] = ' .. rk(inst, 8, 11, 5) .. ' ^ ' .. rk(inst, 6, 10, 1)
	elseif op == 7 then
		lines[#lines + 1] = 'r[' .. A .. '] = not r[' .. B .. ']'
	elseif op == 8 then
		lines[#lines + 1] = 'r[' .. A .. '] = -r[' .. B .. ']'
	elseif op == 9 then
		lines[#lines + 1] = 'r[' .. A .. '] = ' .. rk(inst, 8, 11, 5) .. ' * ' .. rk(inst, 6, 10, 1)
	elseif op == 10 then
		lines[#lines + 1] = 'r[' .. A .. '] = #r[' .. B .. ']'
	elseif op == 11 then
		lines[#lines + 1] = 'r[' .. A .. '] = r[' .. B .. ']'
	elseif op == 12 then
		lines[#lines + 1] = 'r[' .. A .. '] = ' .. tostring(B ~= 0)
		if C ~= 0 then
			lines[#lines + 1] = 'pc = pc + 1'
		end
	elseif op == 13 then
		lines[#lines + 1] = '-- CLOSE r[' .. A .. '] and above'
	elseif op == 14 then
		lines[#lines + 1] = 'r[' .. A .. '] = function(...) error("nested closure proto ' .. tostring(inst[7]) .. ' was not emitted", 2) end'
	elseif op == 15 then
		lines[#lines + 1] = 'env[' .. raw_value(inst[4]) .. '] = r[' .. A .. ']'
	elseif op == 16 then
		for _, line in ipairs(call_lines(inst, false)) do lines[#lines + 1] = line end
	elseif op == 17 then
		lines[#lines + 1] = 'local text = r[' .. B .. ']'
		lines[#lines + 1] = 'for i = ' .. (B + 1) .. ', ' .. C .. ' do text = text .. r[i] end'
		lines[#lines + 1] = 'r[' .. A .. '] = text'
	elseif op == 18 then
		lines[#lines + 1] = 'if (' .. rk(inst, 8, 11, 5) .. ' <= ' .. rk(inst, 6, 10, 1) .. ') ~= ' .. tostring(A ~= 0) .. ' then pc = pc + 1 end'
	elseif op == 19 then
		lines[#lines + 1] = 'if (' .. rk(inst, 8, 11, 5) .. ' < ' .. rk(inst, 6, 10, 1) .. ') ~= ' .. tostring(A ~= 0) .. ' then pc = pc + 1 end'
	elseif op == 20 then
		lines[#lines + 1] = 'r[' .. A .. '] = assert(tonumber(r[' .. A .. ']), "`for` initial value must be a number") - assert(tonumber(r[' .. (A + 2) .. ']), "`for` step must be a number")'
		lines[#lines + 1] = 'r[' .. (A + 1) .. '] = assert(tonumber(r[' .. (A + 1) .. ']), "`for` limit must be a number")'
		lines[#lines + 1] = 'pc = pc + ' .. tostring(inst[2] or 0)
		return lines
	elseif op == 21 then
		lines[#lines + 1] = 'r[' .. A .. '] = ' .. rk(inst, 8, 11, 5) .. ' - ' .. rk(inst, 6, 10, 1)
	elseif op == 22 then
		lines[#lines + 1] = return_line(inst)
		return lines
	elseif op == 23 then
		lines[#lines + 1] = 'r[' .. (A + 1) .. '] = r[' .. B .. ']'
		lines[#lines + 1] = 'r[' .. A .. '] = r[' .. B .. '][' .. rk(inst, 6, 10, 1) .. ']'
	elseif op == 24 then
		lines[#lines + 1] = 'local count, block = ' .. tostring(B) .. ', ' .. tostring(C)
		lines[#lines + 1] = 'if count == 0 then count = top - ' .. tostring(A) .. ' end'
		lines[#lines + 1] = 'local offset = (block - 1) * 50'
		lines[#lines + 1] = 'for i = 1, count do r[' .. A .. '][offset + i] = r[' .. A .. ' + i] end'
	elseif op == 25 then
		lines[#lines + 1] = 'r[' .. A .. '] = getUpvalue(upvalues, ' .. tostring(B) .. ')'
	elseif op == 26 then
		lines[#lines + 1] = 'if (' .. rk(inst, 8, 11, 5) .. ' == ' .. rk(inst, 6, 10, 1) .. ') ~= ' .. tostring(A ~= 0) .. ' then pc = pc + 1 end'
	elseif op == 27 then
		lines[#lines + 1] = 'local count = ' .. tostring(B)
		lines[#lines + 1] = 'if count == 0 then count = varargs.n + 1; top = ' .. tostring(A) .. ' + count - 2 end'
		lines[#lines + 1] = 'for i = 1, count - 1 do r[' .. A .. ' + i - 1] = varargs[i] end'
	elseif op == 28 then
		lines[#lines + 1] = 'r[' .. A .. '][' .. rk(inst, 8, 11, 5) .. '] = ' .. rk(inst, 6, 10, 1)
	elseif op == 29 then
		lines[#lines + 1] = 'r[' .. A .. '] = ' .. rk(inst, 8, 11, 5) .. ' + ' .. rk(inst, 6, 10, 1)
	elseif op == 30 then
		lines[#lines + 1] = 'if (not r[' .. A .. ']) == ' .. tostring(C ~= 0) .. ' then pc = pc + 1 end'
	elseif op == 31 then
		for _, line in ipairs(call_lines(inst, true)) do lines[#lines + 1] = line end
		return lines
	elseif op == 32 then
		lines[#lines + 1] = 'r[' .. A .. '] = ' .. global_expr(inst[4])
	elseif op == 33 then
		lines[#lines + 1] = 'r[' .. A .. '] = ' .. rk(inst, 8, 11, 5) .. ' % ' .. rk(inst, 6, 10, 1)
	elseif op == 34 then
		lines[#lines + 1] = 'r[' .. A .. '] = {}'
	elseif op == 35 then
		lines[#lines + 1] = 'r[' .. A .. '] = r[' .. B .. '][' .. rk(inst, 6, 10, 1) .. ']'
	elseif op == 36 then
		lines[#lines + 1] = 'if (not r[' .. B .. ']) == ' .. tostring(C ~= 0) .. ' then pc = pc + 1 else r[' .. A .. '] = r[' .. B .. '] end'
	elseif op == 37 then
		lines[#lines + 1] = 'local step = r[' .. (A + 2) .. ']'
		lines[#lines + 1] = 'local index = r[' .. A .. '] + step'
		lines[#lines + 1] = 'local limit = r[' .. (A + 1) .. ']'
		lines[#lines + 1] = 'if (step >= 0 and index <= limit) or (step < 0 and index >= limit) then r[' .. A .. '] = index; r[' .. (A + 3) .. '] = index; pc = pc + ' .. tostring(inst[2] or 0) .. ' end'
	else
		lines[#lines + 1] = 'error("unsupported VM opcode ' .. tostring(op) .. ' at pc ' .. tostring(item.pc) .. '")'
	end

	lines[#lines + 1] = next_pc_line(item.pc)
	return lines
end

local function emit_roblox(header, instructions)
	local out = {
		'-- Roblox/Luau runnable output generated from the VM raw instruction listing.',
		'-- It preserves arbitrary VM control flow with a pc dispatcher instead of Lua goto labels.',
		header,
		'',
		'local function deobfuscated(...)',
		'\tlocal env = (getfenv and getfenv()) or _G',
		'\tlocal unpackValues = table.unpack or unpack',
		'\tlocal function pack(...) return { n = select("#", ...), ... } end',
		'\tlocal function unpackRegisters(registers, first, last)',
		'\t\tlocal values = {}',
		'\t\tfor index = first, last do values[#values + 1] = registers[index] end',
		'\t\treturn unpackValues(values, 1, #values)',
		'\tend',
		'\tlocal function getUpvalue(upvalues, index)',
		'\t\tlocal value = upvalues and upvalues[index]',
		'\t\tif type(value) == "table" and value.store then return value.store[value.index] end',
		'\t\treturn value',
		'\tend',
		'\tlocal function setUpvalue(upvalues, index, value)',
		'\t\tlocal slot = upvalues and upvalues[index]',
		'\t\tif type(slot) == "table" and slot.store then slot.store[slot.index] = value end',
		'\tend',
		'\tlocal r, upvalues, varargs = {}, {}, pack(...)',
		'\tlocal pc, top = 1, -1',
		'\twhile true do',
	}

	for index, item in ipairs(instructions) do
		local prefix = index == 1 and '\t\tif' or '\t\telseif'
		out[#out + 1] = prefix .. ' pc == ' .. tostring(item.pc) .. ' then'
		out[#out + 1] = '\t\t\t-- pc ' .. string.format('%04d', item.pc) .. ' ' .. item.op
		for _, line in ipairs(instruction_lines(item)) do
			out[#out + 1] = '\t\t\t' .. line
		end
	end

	out[#out + 1] = '\t\telse'
	out[#out + 1] = '\t\t\treturn'
	out[#out + 1] = '\t\tend'
	out[#out + 1] = '\tend'
	out[#out + 1] = 'end'
	out[#out + 1] = ''
	out[#out + 1] = 'deobfuscated(...)'
	return table.concat(out, '\n') .. '\n'
end

local src = read_all(src_path)
local header, instructions = parse_raw_listing(src)
write_all(out_path, emit_roblox(header, instructions))
print('Wrote Roblox-runnable beautified output to ' .. out_path)
