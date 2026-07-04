local src_path = arg and arg[1] or 'input.obfu.lua'
local out_path = arg and arg[2] or 'input.obfu.deobfuscated.lua'
local luac_path = arg and arg[3] or 'input.obfu.luac'
local root = (arg and arg[0] or ''):gsub('[^\\/]+$', '')
if root == '\\' or root == '/' then
	root = ''
end

local function path_join(a, b)
	if a == '' or a == nil then
		return b
	end
	if a:match('[\\/]$') then
		return a .. b
	end
	return a .. '\\' .. b
end

local function shell_quote(path)
	return '"' .. tostring(path):gsub('"', '\\"') .. '"'
end

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

local d = {}
for i = 1, 34 do
	local code = ({34, 92, 127})[i - 31] or i
	local a, b = string.char(code), string.char(code + 31)
	d[a], d[b] = b, a
end

local function unesc(s)
	return s:gsub('\127(.)', function(ch)
		return d[ch]
	end)
end

local function clone(t)
	local c = {}
	for k, v in pairs(t) do c[k] = v end
	return c
end

local function base93num(s)
	local sum = 0
	for i = 1, #s do
		local ch = s:sub(-i, -i)
		sum = sum + 93 ^ (i - 1) * f[ch]
	end
	return sum
end

local function decompress(a)
	local dict = clone(f)
	local out, sizes, blob = {}, a:match('(.-)|(.*)')
	assert(sizes and blob, 'compressed stream not found')
	local chunks, pos = {}, 1

	for tok in sizes:gmatch('%d+') do
		local count = tonumber(tok)
		local width = #chunks + 1
		chunks[width] = blob:sub(pos, pos + count * width - 1)
		pos = pos + count * width
	end

	local prev
	for width = 1, #chunks do
		for token in chunks[width]:gmatch(('.'):rep(width)) do
			local cur = dict[base93num(token)]
			if prev then
				if cur then
					out[#out + 1] = cur
					dict[#dict + 1] = prev .. cur:sub(1, 1)
				else
					cur = prev .. prev:sub(1, 1)
					out[#out + 1] = cur
					dict[#dict + 1] = cur
				end
			else
				out[1] = cur
			end
			prev = cur
		end
	end

	return unesc(table.concat(out))
end

local function decode_pairs(s)
	local out = {}
	for i = 1, #s, 2 do
		local a, b = s:byte(i, i + 1)
		out[#out + 1] = string.char(((a - 65) + (b - 65) / 8) * 8)
	end
	return table.concat(out)
end

local function normalize_hase_header(raw)
	if raw:sub(1, 6) == 'HASE\18\0' then
		return '\27Lua\81\0' .. raw:sub(7), true
	end
	return raw, false
end

local function read_u32(s, p)
	local a, b, c, d = s:byte(p, p + 3)
	return a + b * 256 + c * 65536 + d * 16777216
end

local function write_u32(n)
	local a = n % 256
	n = (n - a) / 256
	local b = n % 256
	n = (n - b) / 256
	local c = n % 256
	local d = (n - c) / 256
	return string.char(a, b, c, d)
end

local function normalize_reversed_opcodes(raw)
	local chunks = {}
	local pos = 13

	local function emit(a, b)
		chunks[#chunks + 1] = raw:sub(a, b)
	end

	local function skip_string(p)
		local len = read_u32(raw, p)
		return p + 4 + len
	end

	local function walk_function(p)
		local start = p
		p = skip_string(p)
		p = p + 8 + 4

		local code_count = read_u32(raw, p)
		local code_start = p + 4
		local code_end = code_start + code_count * 4 - 1

		emit(start, code_start - 1)
		for i = 0, code_count - 1 do
			local ip = code_start + i * 4
			local inst = read_u32(raw, ip)
			local op = inst % 64
			local standard_op = 37 - op
			inst = inst - op + standard_op
			chunks[#chunks + 1] = write_u32(inst)
		end

		p = code_end + 1

		local constants_count_start = p
		local constants_count = read_u32(raw, p)
		p = p + 4
		for _ = 1, constants_count do
			local tt = raw:byte(p)
			p = p + 1
			if tt == 1 then
				p = p + 1
			elseif tt == 3 then
				p = p + 8
			elseif tt == 4 then
				p = skip_string(p)
			elseif tt ~= 0 then
				error('unsupported constant type ' .. tostring(tt))
			end
		end

		local proto_count_pos = p
		local proto_count = read_u32(raw, p)
		p = p + 4
		emit(constants_count_start, p - 1)
		for _ = 1, proto_count do
			p = walk_function(p)
		end

		local debug_start = p
		local line_count = read_u32(raw, p)
		p = p + 4 + line_count * 4
		local local_count = read_u32(raw, p)
		p = p + 4
		for _ = 1, local_count do
			p = skip_string(p)
			p = p + 8
		end
		local upvalue_count = read_u32(raw, p)
		p = p + 4
		for _ = 1, upvalue_count do
			p = skip_string(p)
		end
		emit(debug_start, p - 1)

		return p
	end

	emit(1, 12)
	local done = walk_function(pos)
	assert(done == #raw + 1, 'bytecode parser stopped at ' .. done .. ' of ' .. #raw)
	return table.concat(chunks)
end

local function extract_outer_loader(src)
	local captured
	local env = {}

	env.loadstring = function(code)
		captured = code
		return function() end
	end
	env.setfenv = function(fn, e)
		return setfenv(fn, e)
	end
	env.getfenv = function()
		return env
	end
	env.unpack = unpack
	env.select = select
	env.pairs = pairs
	env.next = next
	env.table = table
	env.string = string
	env.tonumber = tonumber
	env.tostring = tostring
	env.type = type
	env.typeof = type
	env.pcall = pcall
	env.error = error
	env.warn = function() end
	env.print = function() end
	env.script = nil
	env.require = function()
		return {
			band = function(a, b) return a % (b + 1) end,
			rshift = function(a, b) return math.floor(a / 2 ^ b) end,
			lshift = function(a, b) return a * 2 ^ b end,
		}
	end
	setmetatable(env, {__index = _G})

	local fn, err = loadstring(src)
	assert(fn, err)
	setfenv(fn, env)
	local ticks = 0
	local function watchdog()
		ticks = ticks + 1
		if captured then
			error('__payload_captured__')
		end
		if ticks > 20000 then
			error('__loader_timeout__')
		end
	end
	debug.sethook(watchdog, '', 1000)
	local ok, run_err = pcall(fn)
	debug.sethook()
	if not ok and not captured then
		assert(ok, run_err)
	end
	assert(captured, 'outer loader was not captured')
	return captured
end

local function extract_bytecode_from_loader(loader)
	local final_start, final_end = loader:find('return%s+[%w_]+%s*%(%s*[%w_]+%s*%(%s*[%w_]+%s*%(%s*[%w_]+%s*%(%s*[%w_]+%s*')
	assert(final_start, 'final VM call was not found')

	local final_call, final_call_end = loader:find('%)%s*%)%s*%)%s*%)%s*%(%s*%)', final_end)
	assert(final_call, 'final VM call terminator was not found')

	local prefix = loader:sub(final_start, final_end - 1)
	local _, _, _, _, decode_pairs_name, decompress_name, concat_name =
		prefix:find('return%s+([%w_]+)%s*%(%s*([%w_]+)%s*%(%s*([%w_]+)%s*%(%s*([%w_]+)%s*%(%s*([%w_]+)%s*$')
	assert(decode_pairs_name and decompress_name and concat_name, 'final VM call functions were not parsed')

	local payload_expr = loader:sub(final_end + 1, final_call - 1)
	local table_var = payload_expr:match('([%w_]+)%s*%[')
	assert(table_var, 'payload reference table variable was not found')

	local suffix = loader:sub(final_call_end + 1)
	local ref_expr = suffix:match('%)%s*(%b{})%s*$')
	assert(ref_expr, 'reference table was not found')

	local function eval_expr(expr, env)
		local fn, err = loadstring('return ' .. expr)
		assert(fn, err)
		setfenv(fn, env or {})
		return fn()
	end

	local ref_table = eval_expr(ref_expr, {
		math = math,
		string = string,
		table = table,
		tonumber = tonumber,
		tostring = tostring,
	})

	local payload_env = {
		[table_var] = ref_table,
		math = math,
		string = string,
		table = table,
		tonumber = tonumber,
		tostring = tostring,
	}
	local payload_parts = eval_expr(payload_expr, payload_env)
	local compressed = table.concat(payload_parts)

	return decode_pairs(decompress(compressed))
end

local src = read_all(src_path)
local ok, loader = pcall(extract_outer_loader, src)
if not ok then
	loader = src
end
local raw = extract_bytecode_from_loader(loader)
raw = normalize_hase_header(raw)

local function decompile_candidate(candidate, candidate_path)
	write_all(candidate_path, candidate)
	local cmd = 'java -jar ' .. shell_quote(path_join(root, 'unluac.jar')) .. ' ' .. shell_quote(candidate_path) .. ' 2>&1'
	local pipe = assert(io.popen(cmd, 'r'))
	local result = pipe:read('*a')
	pipe:close()
	if result:find('Exception in thread', 1, true) or result:find('^Exception') or result == '' then
		return false, result
	end
	return true, result
end

local ok_decompile, decompiled = decompile_candidate(raw, luac_path)
if not ok_decompile then
	ok_decompile, decompiled = decompile_candidate(normalize_reversed_opcodes(raw), luac_path)
end

if not ok_decompile then
	write_all(out_path, '')
	error('unluac failed; bytecode was written to ' .. luac_path .. '\n' .. tostring(decompiled))
end

write_all(out_path, decompiled)

print('Wrote bytecode to ' .. luac_path)
print('Wrote decompiled source to ' .. out_path)
