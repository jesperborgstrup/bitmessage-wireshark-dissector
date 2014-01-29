-- bitmessage protocol example
-- declare our protocol
message_commands = { version=true, verack=true, addr=true, inv=true, getdata=true }

bitmessage_header_length = 24

bitmessage_proto = Proto("bitmessage","Bitmessage protocol")
-- create a function to dissect it
function bitmessage_proto.dissector(buffer,pinfo,tree)
    local magic = buffer(0,4):uint()
    if magic ~= 3921589465 then
	    tree:add(bitmessage_proto,buffer(),"Invalid Bitmessage data (invalid magic value " .. buffer(0,4) .. ")" )
	else
	    local offset = 0
		local command = buffer(4,12):stringz()
		local length = buffer(16,4):uint()
		local pdu_length = length + bitmessage_header_length
	    local subtree = tree:add(bitmessage_proto,buffer(),"Bitmessage protocol data (" .. command .. ")")
	    local headertree = subtree:add(buffer(0,bitmessage_header_length), "Header")
		headertree:add(buffer(4,12),"Command: " .. command)
		headertree:add(buffer(16,4),"Payload length: " .. length)
		headertree:add(buffer(20,4),"Checksum: " .. buffer(20,4) )

	    pinfo.cols.protocol = "BITMESSAGE"
	    local commandinfoname = "obj: " .. command
	    if message_commands[command] then
	    	commandinfoname = "msg: " .. command
	    end
		pinfo.cols.info = "["..commandinfoname.."], len: "..length

		if pdu_length > buffer:len() then
			pinfo.desegment_len = pdu_length - buffer:len()
		else
			local payload_buffer = buffer:range(bitmessage_header_length,length)
			do_payload_dissection(payload_buffer,pinfo,subtree,command)
		end
    end
end

function do_payload_dissection(buffer,pinfo,subtree,command)
	if message_commands[command] then
		do_message_dissection(buffer,pinfo,subtree,command)
	else
		do_object_dissection(buffer,pinfo,subtree,command)
	end
end

function do_message_dissection(buffer,pinfo,subtree,command)
	local offset = 0
	if command == "version" then
		subtree = subtree:add(buffer(), "version")
		local version = buffer(0,4):int()
		subtree:add(buffer(0,4), "Version: " .. version)
		subtree:add(buffer(4,8), "Services: " .. services_bitfield_to_string( buffer(4,8) ) )
		subtree:add(buffer(12,8), "Timestamp: " .. uint_to_date(buffer(12,8):uint64()))
		offset = 20
		offset = offset + parse_net_addr(buffer(offset,26),subtree:add(buffer(offset,26),"Receiver address"),version,false)
		offset = offset + parse_net_addr(buffer(offset,26),subtree:add(buffer(offset,26),"Sender address"),version,false)
		subtree:add(buffer(offset,8),"Nonce: " .. buffer(72,8) )
		offset = offset + 8
		local ua, ua_len = parse_var_string( buffer:range( 80 ) )
		subtree:add(buffer(80,ua_len), "User agent: " .. ua )
		offset = offset + ua_len
		local stream_nums, sn_len = parse_var_int_list( buffer:range( offset ) )
		subtree:add(buffer(offset,sn_len), "Stream numbers: [" .. table.concat( stream_nums, ", " ) .. "]" )
	elseif command == "verack" then
		-- No payload in verack
	elseif command == "addr" then
		subtree = subtree:add(buffer(), "addr")
		local addr_count, offset = parse_var_int(buffer)
		subtree:add(buffer(0,offset), "Address count: " .. addr_count)
		for i = 1, addr_count do
			local addr_tree = subtree:add(buffer(offset), "Address " .. i)
			local version = 1
			if buffer(offset,4):uint() == 0 then
				-- Assume version 2 (time length = 8)
				version = 2
			end
			local offset_add = parse_net_addr(buffer(offset),addr_tree,version,true)
			addr_tree:set_len(offset_add)
			offset = offset + offset_add
		end
	elseif command == "inv" then
		subtree = subtree:add(buffer(), "inv")
		local inv_count, offset = parse_var_int(buffer)
		subtree:add(buffer(0,offset), "Inventory count: " .. inv_count)
	elseif command == "getdata" then
		subtree = subtree:add(buffer(), "getdata")
		local inv_count, offset = parse_var_int(buffer)
		subtree:add(buffer(0,offset), "Inventory count: " .. inv_count)
	else
		subtree:add(buffer(),"Payload: " .. buffer() )
	end
end

function do_object_dissection(buffer,pinfo,subtree,command)
	local offset = 0
	if command == "getpubkey" then
		subtree = subtree:add(buffer(), "getpubkey")
		subtree:add(buffer(0,8), "POW nonce: " .. buffer(0,8))
		subtree:add(buffer(8,8), "Time: " .. uint_to_date( buffer(8,8):uint64()))
		offset = 16
		local addr_ver, offset_add = parse_var_int(buffer(offset))
		subtree:add(buffer(offset,offset_add), "Address version: " .. addr_ver)
		offset = offset + offset_add
		local stream_no, offset_add = parse_var_int(buffer(offset))
		subtree:add(buffer(offset,offset_add), "Stream number: " .. stream_no)
		offset = offset + offset_add
		if addr_ver <= 3 then
			subtree:add(buffer(offset,20), "RipeMD hash: " .. buffer(offset,20))
			offset = offset + 20
		end
		if addr_ver >= 4 then
			subtree:add(buffer(offset,32), "Tag: " .. buffer(offset,32) )
			offset = offset + 32
		end
	elseif command == "pubkey" then
		subtree = subtree:add(buffer(), "pubkey")
		subtree:add(buffer(0,8), "POW nonce: " .. buffer(0,8))
		subtree:add(buffer(8,8), "Time: " .. uint_to_date( buffer(8,8):uint64()))
		offset = 16
		local addr_ver, offset_add = parse_var_int(buffer(offset))
		subtree:add(buffer(offset,offset_add), "Address version: " .. addr_ver)
		offset = offset + offset_add
		local stream_no, offset_add = parse_var_int(buffer(offset))
		subtree:add(buffer(offset,offset_add), "Stream number: " .. stream_no)
		offset = offset + offset_add
		if addr_ver == 2 or addr_ver == 3 then
			subtree:add(buffer(offset,4), "Behaviour bitfield: " .. buffer(offset,4):bitfield(0,4))
			offset = offset + 4
			subtree:add(buffer(offset,64), "Public signing key: " .. buffer(offset,64))
			offset = offset + 64
			subtree:add(buffer(offset,64), "Public encryption key: " .. buffer(offset,64))
			offset = offset + 64
			if addr_ver == 3 then
				-- Version 3 pubkey
				local nonce_trials, int_len = parse_var_int(buffer(offset))
				subtree:add(buffer(offset,int_len), "Nonce trials per byte: " .. nonce_trials)
				offset = offset + int_len
				local extra_bytes, int_len = parse_var_int(buffer(offset))
				subtree:add(buffer(offset,int_len), "Extra bytes: " .. extra_bytes)
				offset = offset + int_len
				local sig_len, int_len = parse_var_int(buffer(offset))
				offset = offset + int_len
				subtree:add(buffer(offset,sig_len), "ECDSA signature: " .. buffer(offset,sig_len))
				offset = offset + sig_len
			end
		elseif addr_ver == 4 then
			subtree:add(buffer(offset,32), "Tag: " .. buffer(offset,32) )
			offset = offset + 32
			local encrypted_len = buffer:len() - offset
			parse_encrypted_payload(buffer(offset,encrypted_len),subtree:add(buffer(offset,encrypted_len), "Encrypted payload"))
		end
	elseif command == "msg" then
		subtree = subtree:add(buffer(), "msg")
		subtree:add(buffer(offset,8), "POW nonce: " .. buffer(offset,8))
		offset = offset + 8
		subtree:add(buffer(offset,8), "Time: " .. uint_to_date( buffer(offset,8):uint64()))
		offset = offset + 8
		local stream_no, offset_add = parse_var_int(buffer(offset))
		subtree:add(buffer(offset,offset_add), "Stream number: " .. stream_no)
		offset = offset + offset_add
		local encrypted_len = buffer:len() - offset
		if encrypted_len < 54 then
			subtree:add(buffer(offset,encrypted_len),"(Short encrypted payload, possibly an acknowledgement)")
		else
			parse_encrypted_payload(buffer(offset,encrypted_len),subtree:add(buffer(offset,encrypted_len), "Encrypted payload"))
		end
	elseif command == "broadcast" then
		subtree = subtree:add(buffer(), "broadcast")
		subtree:add(buffer(offset,8), "POW nonce: " .. buffer(offset,8))
		offset = offset + 8
		subtree:add(buffer(offset,8), "Time: " .. uint_to_date( buffer(offset,8):uint64()))
		offset = offset + 8
		local broadcast_ver, offset_add = parse_var_int(buffer(offset))
		subtree:add(buffer(offset,offset_add), "Broadcast version: " .. broadcast_ver)
		offset = offset + offset_add
		local stream_no, offset_add = parse_var_int(buffer(offset))
		subtree:add(buffer(offset,offset_add), "Stream number: " .. stream_no)
		offset = offset + offset_add
		if broadcast_ver >= 3 then
			subtree:add(buffer(offset,32), "Tag: " .. buffer(offset,32) )
			offset = offset + 32
		end
		parse_encrypted_payload(buffer(offset,encrypted_len),subtree:add(buffer(offset,encrypted_len), "Encrypted payload"))		
	end
end

function parse_net_addr(buffer,subtree,version,include_time_and_stream)
	local offset = 0
	if include_time_and_stream then
		if version == 1 then
			subtree:add(buffer(0,4), "Time: " .. uint_to_date( buffer(0,4):uint()))
			offset = 4
		elseif version == 2 then
			subtree:add(buffer(0,8), "Time: " .. uint_to_date( buffer(0,8):uint64()))
			offset = 8
		end
		subtree:add(buffer(offset,4), "Stream number: " .. buffer(offset,4):uint() )
		offset = offset + 4
	end
	subtree:add(buffer(offset,8), "Services " .. services_bitfield_to_string( buffer(offset,8 ) ) )
	offset = offset + 8
	subtree:add(buffer(offset,16), "Address: " .. ipv6_to_string( buffer( offset, 16 ) ) )
	offset = offset + 16
	subtree:add(buffer(offset,2), "Port: " .. buffer(offset,2):uint() )
	offset = offset + 2

	return offset
end

function parse_encrypted_payload(buffer,subtree)
	local offset = 0
	subtree:add(buffer(offset,16),"Initialization vector: " .. buffer(offset,16))
	offset = offset + 16
	subtree:add(buffer(offset,2),"Elliptic curve type: " .. buffer(offset,2):uint())
	offset = offset + 2
	local x_len = buffer(offset,2):uint()
	subtree:add(buffer(offset,2), "X length: " .. x_len)
	offset = offset + 2
	subtree:add(buffer(offset,x_len),"X : " .. buffer(offset,x_len))
	offset = offset + x_len
	local y_len = buffer(offset,2):uint()
	subtree:add(buffer(offset,2), "Y length: " .. y_len)
	offset = offset + 2
	subtree:add(buffer(offset,x_len),"Y : " .. buffer(offset,y_len))
	offset = offset + y_len
	local encrypted_len = buffer:len() - offset - 32
	subtree:add(buffer(offset,encrypted_len), "(Cipher text)")
	offset = offset + encrypted_len
	subtree:add(buffer(offset,32), "HMAC: " .. buffer(offset, 32))
	offset = offset + 32
end

function ipv6_to_string(buffer)
	-- For now, only support IPv4 mapped address (the last 4 bytes of the 16 byte string is the IPv4 address)
	return "IPv4: " .. buffer(12,1):uint() .. "." .. buffer(13,1):uint() .. "." .. buffer(14,1):uint() .. "." .. buffer(15,1):uint()
end

function parse_var_int(buffer)
	local marker = buffer(0,1):uint()
	if marker < 0xfd then
		return marker, 1
	elseif marker == 0xfd then
		return buffer(1,2):uint(), 3
	elseif marker == 0xfe then
		return buffer(1,4):uint(), 5
	else
		return buffer(1,8):uint64(), 9
	end
end

function parse_var_string(buffer)
	local len, offset = parse_var_int(buffer)
	if len == 0 then
		return "", 1
	else
		local str = buffer(offset,len):string()
		return str, offset + len
	end
end

function parse_var_int_list(buffer)
	local len, offset = parse_var_int(buffer)
	local result = {}
	for i = 1, len do
		local entry, offset_add = parse_var_int(buffer:range(offset))
		table.insert( result, entry )
		offset = offset + offset_add
	end
	return result, offset
end

function services_bitfield_to_string(buffer)
	return buffer(0,8):bitfield(0,8)
end


function uint_to_date(uint)
	-- http://ask.wireshark.org/answer_link/11697/
	return format_date(tonumber(tostring(uint)))
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 8444
tcp_table:add(8444,bitmessage_proto)