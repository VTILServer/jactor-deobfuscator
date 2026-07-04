local root = (arg and arg[0] or ''):gsub('[^\\/]+$', '')
if root == '\\' or root == '/' then
	root = ''
end
local input_path = assert(arg and arg[1], 'usage: lua deobfuscate_rbxmx.lua input.rbxmx [output.rbxmx]')

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

local function ps_quote(value)
	return "'" .. tostring(value):gsub("'", "''") .. "'"
end

local function file_exists(path)
	local fh = io.open(path, 'rb')
	if fh then
		fh:close()
		return true
	end
	return false
end

local function dirname(path)
	local d = path:match('^(.*)[\\/]')
	return d and d ~= '' and d or '.'
end

local function basename_no_ext(path)
	local name = path:match('([^\\/]+)$') or path
	return (name:gsub('%.[^.]*$', ''))
end

local function sanitize_name(name)
	name = tostring(name or 'Script')
	name = name:gsub('&quot;', '"'):gsub('&apos;', "'"):gsub('&lt;', '<'):gsub('&gt;', '>'):gsub('&amp;', '&')
	name = name:gsub('[<>:"/\\|%?%*%c]', '_'):gsub('%s+', '_')
	if name == '' then
		name = 'Script'
	end
	return name
end

local function xml_decode(text)
	text = text or ''
	local cdata = text:match('^%s*<!%[CDATA%[(.*)%]%]>%s*$')
	if cdata then
		return cdata
	end
	text = text:gsub('&lt;', '<')
	text = text:gsub('&gt;', '>')
	text = text:gsub('&quot;', '"')
	text = text:gsub('&apos;', "'")
	text = text:gsub('&amp;', '&')
	return text
end

local function xml_encode(text)
	text = text or ''
	text = text:gsub('&', '&amp;')
	text = text:gsub('<', '&lt;')
	text = text:gsub('>', '&gt;')
	return text
end

local function command_ok(cmd)
	local ok, why, code = os.execute(cmd)
	if type(ok) == 'number' then
		return ok == 0
	end
	return ok == true and code == 0
end

local function run_lua(script, input_file, output_file, extra)
	local cmd = table.concat({
		'lua',
		shell_quote(path_join(root, script)),
		shell_quote(input_file),
		shell_quote(output_file),
		extra and shell_quote(extra) or nil,
	}, ' ') .. ' >nul 2>nul'
	return command_ok(cmd) and file_exists(output_file)
end

local function run_normal(input_file, output_file, temp_luac)
	if not file_exists(path_join(root, 'extract_payload.lua')) or not file_exists(path_join(root, 'unluac.jar')) then
		return false
	end

	local extract_cmd = table.concat({
		'lua',
		shell_quote(path_join(root, 'extract_payload.lua')),
		shell_quote(input_file),
		shell_quote(temp_luac),
	}, ' ') .. ' >nul 2>nul'
	if not command_ok(extract_cmd) or not file_exists(temp_luac) then
		return false
	end

	local decompile_cmd = 'java -jar ' .. shell_quote(path_join(root, 'unluac.jar')) .. ' ' .. shell_quote(temp_luac) .. ' > ' .. shell_quote(output_file) .. ' 2>nul'
	return command_ok(decompile_cmd) and file_exists(output_file)
end

local function looks_useful(path)
	local data = file_exists(path) and read_all(path) or ''
	if #data < 8 then
		return false
	end
	if data:find('Exception in thread', 1, true) or data:find('stack traceback', 1, true) then
		return false
	end
	return true
end

local function deobfuscate_script(source_path, output_path, work_dir)
	local source = read_all(source_path)
	local candidates = {}

	if source:find('Jac', 1, true) or source:find('invalid Lua signature', 1, true) then
		candidates[#candidates + 1] = 'obfu'
	end
	if source:find('OP_', 1, true) or source:find('+=', 1, true) or source:find('continue', 1, true) then
		candidates[#candidates + 1] = 'obfuv45'
		candidates[#candidates + 1] = 'obfuv4'
		candidates[#candidates + 1] = 'obfuv3'
	end
	candidates[#candidates + 1] = 'normal'
	candidates[#candidates + 1] = 'obfu'
	candidates[#candidates + 1] = 'obfuv45'
	candidates[#candidates + 1] = 'obfuv4'
	candidates[#candidates + 1] = 'obfuv3'

	local tried = {}
	for _, kind in ipairs(candidates) do
		if not tried[kind] then
			tried[kind] = true
			local temp_out = path_join(work_dir, 'try_' .. kind .. '.lua')
			local temp_luac = path_join(work_dir, 'try_' .. kind .. '.luac')
			local ok = false

			if kind == 'normal' then
				ok = run_normal(source_path, temp_out, temp_luac)
			elseif kind == 'obfu' then
				ok = run_lua('deobfu_obfu.lua', source_path, temp_out, temp_luac)
			elseif kind == 'obfuv45' then
				ok = run_lua('deobfu_vm_v45.lua', source_path, temp_out)
			elseif kind == 'obfuv3' then
				ok = run_lua('deobfu_vm_v3.lua', source_path, temp_out)
			elseif kind == 'obfuv4' then
				ok = run_lua('deobfu_vm_v4.lua', source_path, temp_out)
			end

			if ok and looks_useful(temp_out) then
				write_all(output_path, read_all(temp_out))
				return kind
			end
		end
	end

	write_all(output_path, source)
	return 'unchanged'
end

local function find_item_name(xml, source_start)
	local item_start
	local pos = 1
	while true do
		local s = xml:find('<Item[%s>]', pos)
		if not s or s > source_start then
			break
		end
		item_start = s
		pos = s + 5
	end
	if not item_start then
		return 'Script'
	end
	local item_end = xml:find('</Item>', source_start, true) or source_start
	local chunk = xml:sub(item_start, item_end)
	local name = chunk:match('<string%s+name="Name">(.-)</string>')
	return sanitize_name(xml_decode(name or 'Script'))
end

local model_text = read_all(input_path)
local base_dir = dirname(input_path)
local model_name = basename_no_ext(input_path)
local dump_dir = path_join(base_dir, model_name)
local output_path = arg[2] or path_join(base_dir, model_name .. '.deobfuscated.rbxmx')

command_ok('mkdir ' .. shell_quote(dump_dir) .. ' >nul 2>nul')

local pieces = {}
local cursor = 1
local count = 0
local changed = 0

while true do
	local start_pos, tag_end, tag_name, attrs = model_text:find('<([%w_]+)([^>]-%sname="Source"[^>]*)>', cursor)
	if not start_pos then
		pieces[#pieces + 1] = model_text:sub(cursor)
		break
	end

	local close_start, close_end = model_text:find('</' .. tag_name .. '>', tag_end + 1, true)
	if not close_start then
		pieces[#pieces + 1] = model_text:sub(cursor)
		break
	end

	count = count + 1
	local script_name = find_item_name(model_text, start_pos)
	local prefix = string.format('%03d_%s', count, script_name)
	local raw_source = model_text:sub(tag_end + 1, close_start - 1)
	local source = xml_decode(raw_source)
	local source_path = path_join(dump_dir, prefix .. '.lua')
	local output_lua = path_join(dump_dir, prefix .. '.deobfuscated.lua')
	local work_dir = path_join(dump_dir, prefix .. '_work')

	command_ok('mkdir ' .. shell_quote(work_dir) .. ' >nul 2>nul')
	write_all(source_path, source)

	local mode = deobfuscate_script(source_path, output_lua, work_dir)
	local replacement = read_all(output_lua)
	if replacement ~= source then
		changed = changed + 1
	end

	pieces[#pieces + 1] = model_text:sub(cursor, tag_end)
	pieces[#pieces + 1] = xml_encode(replacement)
	cursor = close_start

	print(string.format('[%03d] %s -> %s', count, script_name, mode))
end

write_all(output_path, table.concat(pieces))
print(string.format('Extracted %d Source value(s) to %s', count, dump_dir))
print(string.format('Replaced %d Source value(s)', changed))
print('Wrote patched model to ' .. output_path)
