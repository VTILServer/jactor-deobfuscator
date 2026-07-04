local src_path = arg and arg[1] or [[C:\Users\ricky\Documents\Playground\input.lua]]
local out_path = arg and arg[2] or [[C:\Users\ricky\Documents\Playground\output.luac]]

local fh = assert(io.open(src_path, 'rb'))
local src = fh:read('*a')
fh:close()

local function normalize_lua51_chunk_header(raw)
	if raw:sub(1, 6) == '\27Jac\67\5' then
		return '\27Lua\81\0' .. raw:sub(7), true
	end
	return raw, false
end

local payload = src:match('return%s+p%(%s*m%(%s*a%(%s*e%(%s*"(.+)"%s*%)%s*%)%s*%)%s*,%s*getfenv%(%s*%)%s*%)%s*%(%s*%)')
assert(payload, 'encoded payload not found')

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

local function decode_e(a)
	local dict = clone(f)
	local out, sizes, blob = {}, a:match('(.-)|(.*)')
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

local function decode_a(s)
	local out = {}
	local p = 1
	for i = 1, #s, 2 do
		local pair = s:sub(i, i + 1)
		local b = ((pair:byte(1) - 65) + (pair:byte(2) - 65) / 8) * 8
		out[p] = string.char(b)
		p = p + 1
	end
	return table.concat(out)
end

local raw, normalized_header = normalize_lua51_chunk_header(decode_a(decode_e(payload)))
local of = assert(io.open(out_path, 'wb'))
of:write(raw)
of:close()

print('Wrote '..#raw..' bytes to '..out_path)
print('Magic:', raw:byte(1), raw:byte(2), raw:byte(3), raw:byte(4))
if normalized_header then
	print('Normalized Lua 5.1 header: \\27Jac 0x43 5 -> \\27Lua 0x51 0')
end
