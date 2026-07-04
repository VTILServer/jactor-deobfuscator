local src_path = arg and arg[1] or 'input.obfuv3.lua'
local out_path = arg and arg[2] or 'input.obfuv3.deobfuscated.lua'
local luac_path = arg and arg[3] or 'input.obfuv3.luac'

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
	for k, v in pairs(t) do
		out[k] = v
	end
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
	assert(spans and content, 'compressed payload is malformed')

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

local function decode_pairs(s)
	return (s:gsub('..', function(pair)
		local a, b = pair:byte(1, 2)
		return string.char((a - 65) * 16 + b - 66)
	end))
end

local function decode_base8_pairs(s)
	return (s:gsub('..', function(pair)
		local a, b = pair:byte(1, 2)
		return string.char(((a - 65) + (b - 65) / 8) * 8)
	end))
end

local function read_lua_string(src, quote_pos)
	local quote = src:sub(quote_pos, quote_pos)
	assert(quote == '"' or quote == "'", 'expected Lua string')

	local out = {}
	local pos = quote_pos + 1
	while pos <= #src do
		local ch = src:sub(pos, pos)
		if ch == quote then
			return table.concat(out), pos
		end
		if ch == '\\' then
			local next_ch = src:sub(pos + 1, pos + 1)
			if next_ch:match('%d') then
				local digits = src:sub(pos + 1):match('^%d%d?%d?')
				out[#out + 1] = string.char(tonumber(digits))
				pos = pos + 1 + #digits
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

local function normalize_lua51_header(raw)
	if raw:sub(1, 6) == '\27Jac\67\5' then
		return '\27Lua\81\0' .. raw:sub(7), true
	end
	if raw:sub(1, 6) == 'HASE\18\0' then
		return '\27Lua\81\0' .. raw:sub(7), true
	end
	return raw, false
end

local function extract_best_chunk(src)
	local best_error
	local start = 1
	while true do
		local call_start, quote_pos = src:find('e%(%s*"', start)
		if not call_start then
			break
		end

		local payload = read_lua_string(src, quote_pos)
		if payload:find('|', 1, true) then
			local ok, decompressed = pcall(decompress, payload)
			if ok then
				for _, decoder in ipairs({decode_pairs, decode_base8_pairs}) do
					local raw = decoder(decompressed)
					if raw:sub(1, 4) == '\27Jac' or raw:sub(1, 4) == '\27Lua' or raw:sub(1, 4) == 'HASE' then
						return raw
					end
					best_error = 'payload decoded but was not bytecode; first bytes: '
						.. table.concat({raw:byte(1, math.min(8, #raw))}, ',')
				end
			else
				best_error = decompressed
			end
		end

		start = quote_pos + #payload + 2
	end

	error('no bytecode payload found' .. (best_error and (': ' .. best_error) or ''))
end

local src = read_all(src_path)
local raw = extract_best_chunk(src)
local normalized
raw, normalized = normalize_lua51_header(raw)
write_all(luac_path, raw)

local cmd = 'java -jar "unluac.jar" "' .. luac_path .. '" 2>&1'
local pipe = assert(io.popen(cmd, 'r'))
local decompiled = pipe:read('*a')
pipe:close()

if decompiled:find('Exception in thread', 1, true) or decompiled == '' then
	write_all(out_path, '')
	error('unluac failed; bytecode was written to ' .. luac_path .. '\n' .. decompiled)
end

write_all(out_path, decompiled)

print('Wrote bytecode to ' .. luac_path)
print('Wrote decompiled source to ' .. out_path)
if normalized then
	print('Normalized custom Lua 5.1 header')
end
