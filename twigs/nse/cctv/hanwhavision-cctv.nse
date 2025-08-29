local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects Hanwha Vision (Wisenet) CCTV cameras on the network by probing common ports and protocols.
Supports HTTP, HTTPS, RTSP, SIP, and SNMP detection methods.
Only outputs make, model, version and firmware information for confirmed Hanwha Vision devices.
]]

---
-- @usage
-- nmap --script hanwha-cctv-detect -sU -sS -p U:161,T:80,443,554,5060,8080,8081,8090,4321,37777 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 161/udp open  snmp
-- | hanwha-cctv-detect: 
-- |   Make: Hanwha Vision
-- |   Model: XNP-6320H
-- |   Description: Wisenet Network Camera
-- |_  SNMP Community: public

author = "Custom NSE Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Port rule for all supported protocols
portrule = function(host, port)
  local tcp_ports = {80, 443, 554, 5060, 8080, 8081, 8090, 4321, 37777, 9000, 10554, 5985}
  local udp_ports = {161, 5060}
  
  -- Allow open|filtered for UDP ports (common for UDP services)
  if port.state ~= "open" and not (port.protocol == "udp" and port.state == "open|filtered") then
    return false
  end
  
  if port.protocol == "tcp" then
    for _, p in ipairs(tcp_ports) do
      if port.number == p then return true end
    end
    return port.service == "http" or port.service == "https" or port.service == "rtsp" or 
           port.service == "http-alt" or port.service == "sip"
  elseif port.protocol == "udp" then
    for _, p in ipairs(udp_ports) do
      if port.number == p then return true end
    end
    return port.service == "snmp" or port.service == "sip"
  end
  
  return false
end

-- Extract Hanwha Vision model numbers
local function extract_hanwha_model(text)
  if not text then return nil end
  
  local patterns = {
    -- Common Hanwha/Wisenet model patterns
    "XN[DPOVEFSKBTLH]%-[%w%-]+",     -- XNP-, XND-, XNO-, XNV-, etc.
    "HN[DPOVEFSKBTLH]%-[%w%-]+",     -- HNP-, HND-, HNO-, HNV-, etc. 
    "QN[DPOVEFSKBTLH]%-[%w%-]+",     -- QNP-, QND-, QNO-, QNV-, etc.
    "TN[DPOVEFSKBTLH]%-[%w%-]+",     -- TNP-, TND-, TNO-, TNV-, etc.
    "AN[DPOVEFSKBTLH]%-[%w%-]+",     -- ANP-, AND-, ANO-, ANV-, etc.
    "PN[DPOVEFSKBTLH]%-[%w%-]+",     -- PNP-, PND-, PNO-, PNV-, etc.
    "SN[DPOVEFSKBTLH]%-[%w%-]+",     -- Legacy Samsung models
    "TID%-[%w%-]+",                  -- TID- models (like TID-600R)
    "Wisenet.-(XN[DPOVEFSKBTLH]%-[%w%-]+)", -- Model within Wisenet text
    "Hanwha.-(XN[DPOVEFSKBTLH]%-[%w%-]+)",  -- Model within Hanwha text
    "Hanwha Vision ([TXH][%w%-]+)",  -- Hanwha Vision TID-600R format
    "Vision ([TXH][%w%-]+)",         -- Vision TID-600R format
  }
  
  for _, pattern in ipairs(patterns) do
    local match = string.match(text, pattern)
    if match then
      return match
    end
  end
  return nil
end

-- Check if device is Hanwha Vision
local function is_hanwha_device(text)
  if not text then return false end
  local lower_text = string.lower(text)
  return string.match(lower_text, "hanwha") or 
         string.match(lower_text, "wisenet") or
         string.match(lower_text, "samsung techwin") or
         string.match(lower_text, "techwin") or
         string.match(lower_text, "hanwha vision") or
         string.match(lower_text, "hanwha%-vision")
end

-- Extract version information
local function extract_versions(text)
  if not text then return {} end
  
  local versions = {}
  local patterns = {
    {pattern = "[Vv]ersion[:%s]*([%d%._%w%-]+)", key = "software"},
    {pattern = "[Ff]irmware[:%s]*([%d%._%w%-]+)", key = "firmware"},
    {pattern = "SW[_%s]*[Vv]er[:%s]*([%d%._%w%-]+)", key = "software"},
    {pattern = "FW[_%s]*[Vv]er[:%s]*([%d%._%w%-]+)", key = "firmware"},
    {pattern = "Build[:%s]*([%d%._%w%-]+)", key = "build"},
    {pattern = "App[:%s]*([%d%._%w%-]+)", key = "application"},
  }
  
  for _, p in ipairs(patterns) do
    local match = string.match(text, p.pattern)
    if match then
      versions[p.key] = match
    end
  end
  
  return versions
end

-- Extract User-Agent information from SIP headers
local function extract_user_agent(text)
  if not text then return nil end
  
  -- Look for User-Agent header in SIP response
  local user_agent = string.match(text, "User%-Agent:%s*([^\r\n]+)")
  if not user_agent then
    user_agent = string.match(text, "user%-agent:%s*([^\r\n]+)")
  end
  if not user_agent then
    user_agent = string.match(text, "Server:%s*([^\r\n]+)")
  end
  if not user_agent then
    user_agent = string.match(text, "server:%s*([^\r\n]+)")
  end
  
  return user_agent
end

-- Extract additional SIP header information
local function extract_sip_info(text)
  if not text then return {} end
  
  local info = {}
  
  -- Extract various SIP headers that might contain device info
  local patterns = {
    {pattern = "User%-Agent:%s*([^\r\n]+)", key = "user_agent"},
    {pattern = "user%-agent:%s*([^\r\n]+)", key = "user_agent"},
    {pattern = "Server:%s*([^\r\n]+)", key = "server"},
    {pattern = "server:%s*([^\r\n]+)", key = "server"},
    {pattern = "Contact:%s*([^\r\n]+)", key = "contact"},
    {pattern = "contact:%s*([^\r\n]+)", key = "contact"},
    {pattern = "Via:%s*([^\r\n]+)", key = "via"},
    {pattern = "via:%s*([^\r\n]+)", key = "via"},
    {pattern = "From:%s*([^\r\n]+)", key = "from"},
    {pattern = "from:%s*([^\r\n]+)", key = "from"},
  }
  
  for _, p in ipairs(patterns) do
    local match = string.match(text, p.pattern)
    if match and not info[p.key] then
      info[p.key] = match
    end
  end
  
  return info
end

-- SIP detection for port 5060
local function probe_sip(host, port)
  local socket = nmap.new_socket()
  local status, err
  
  socket:set_timeout(10000)  -- Increased timeout for UDP
  
  if port.protocol == "udp" then
    status, err = socket:connect(host, port, "udp")
  else
    status, err = socket:connect(host, port, "tcp")
  end
  
  if not status then
    socket:close()
    return nil
  end
  
  -- Send SIP OPTIONS request
  local protocol_type = string.upper(port.protocol)
  local sip_request = string.format(
    "OPTIONS sip:%s:%d SIP/2.0\r\n" ..
    "Via: SIP/2.0/%s %s:5060;branch=z9hG4bK%d\r\n" ..
    "From: <sip:scanner@%s:5060>;tag=%d\r\n" ..
    "To: <sip:%s:%d>\r\n" ..
    "Call-ID: %d@%s\r\n" ..
    "CSeq: 1 OPTIONS\r\n" ..
    "Contact: <sip:scanner@%s:5060>\r\n" ..
    "Max-Forwards: 70\r\n" ..
    "User-Agent: NSE-Hanwha-Detect/1.0\r\n" ..
    "Accept: application/sdp\r\n" ..
    "Content-Length: 0\r\n\r\n",
    host.ip, port.number,
    protocol_type, host.ip, math.random(1000000, 9999999),
    host.ip, math.random(10000, 99999),
    host.ip, port.number,
    math.random(1000000, 9999999), host.ip,
    host.ip
  )
  
  status, err = socket:send(sip_request)
  if not status then
    socket:close()
    return nil
  end
  
  -- For UDP, try multiple receives as response might be fragmented
  local response = ""
  local attempts = 0
  local max_attempts = 3
  
  while attempts < max_attempts do
    local partial_response
    status, partial_response = socket:receive()
    
    if status and partial_response then
      response = response .. partial_response
      -- Check if we have a complete SIP response
      if string.match(response, "SIP/2%.0%s+%d+") and 
         (string.match(response, "\r\n\r\n") or string.match(response, "Content%-Length:%s*0")) then
        break
      end
    else
      attempts = attempts + 1
    end
  end
  
  socket:close()
  
  if response and string.len(response) > 0 then
    -- Extract SIP header information
    local sip_info = extract_sip_info(response)
    local user_agent = sip_info.user_agent
    
    -- Combine all text sources for analysis
    local all_text_sources = {
      response,
      sip_info.user_agent or "",
      sip_info.server or "",
      sip_info.contact or "",
      sip_info.via or "",
      sip_info.from or ""
    }
    local full_text = table.concat(all_text_sources, " ")
    
    if is_hanwha_device(full_text) then
      local result = {
        make = "Hanwha Vision",
        port = port.number,
        protocol = "sip"
      }
      
      if user_agent then
        result.user_agent = user_agent
      end
      
      -- Try to extract model from all available text
      result.model = extract_hanwha_model(full_text)
      
      -- If no model found in headers, try extracting from any part of response
      if not result.model then
        -- Look for model patterns in the entire response
        result.model = extract_hanwha_model(response)
      end
      
      -- Look for Wisenet branding
      if string.match(full_text, "[Ww]isenet") then
        result.brand = "Wisenet"
      end
      
      -- Extract version information from all sources
      local versions = extract_versions(full_text)
      result.software_version = versions.software
      result.firmware_version = versions.firmware
      result.build_version = versions.build
      result.application_version = versions.application
      
      -- Store raw response for debugging (can be removed later)
      result.raw_response = response
      
      return result
    end
  end
  
  return nil
end

-- SNMP detection using system command
local function probe_snmp(host, port)
  local communities = {"public", "private", "admin", "hanwha", "wisenet", "default"}
  
  for _, community in ipairs(communities) do
    -- Get system description
    local cmd = string.format("timeout 5 snmpget -v2c -c %s -Ovq %s 1.3.6.1.2.1.1.1.0 2>/dev/null", 
                             community, host.ip)
    
    local handle = io.popen(cmd)
    if handle then
      local description = handle:read("*a")
      handle:close()
      
      if description and string.len(description) > 0 then
        description = string.gsub(description, '"', '')
        description = string.gsub(description, '^\n*(.-)%s*$', '%1')
        
        if is_hanwha_device(description) then
          local result = {
            make = "Hanwha Vision",
            description = description,
            port = port.number,
            protocol = "snmp",
            community = community
          }
          
          -- Try to get system name for model
          local cmd2 = string.format("timeout 5 snmpget -v2c -c %s -Ovq %s 1.3.6.1.2.1.1.5.0 2>/dev/null",
                                   community, host.ip)
          local handle2 = io.popen(cmd2)
          if handle2 then
            local sysname = handle2:read("*a")
            handle2:close()
            
            if sysname then
              sysname = string.gsub(sysname, '"', '')
              sysname = string.gsub(sysname, '^\n*(.-)%s*$', '%1')
              result.model = extract_hanwha_model(sysname) or extract_hanwha_model(description)
            end
          end
          
          -- Try to get system location for additional info
          local cmd3 = string.format("timeout 5 snmpget -v2c -c %s -Ovq %s 1.3.6.1.2.1.1.6.0 2>/dev/null",
                                   community, host.ip)
          local handle3 = io.popen(cmd3)
          if handle3 then
            local location = handle3:read("*a")
            handle3:close()
            
            if location and string.len(location) > 0 then
              location = string.gsub(location, '"', '')
              location = string.gsub(location, '^\n*(.-)%s*$', '%1')
              if location ~= "Unknown" and location ~= "" then
                result.location = location
              end
            end
          end
          
          -- Extract version info
          local versions = extract_versions(description)
          result.software_version = versions.software
          result.firmware_version = versions.firmware
          result.build_version = versions.build
          
          return result
        end
      end
    end
  end
  
  return nil
end

-- HTTP/HTTPS detection
local function probe_http(host, port, ssl)
  local paths = {
    "/", 
    "/cgi-bin/main-cgi", 
    "/stw-cgi/system.cgi", 
    "/cgi-bin/system_http.cgi",
    "/cgi-bin/main-cgi?page_name=main",
    "/wisenet/main",
    "/admin/basic.cgi",
    "/setup/network_setup.cgi"
  }
  
  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    
    if response and response.status then
      local content = response.body or ""
      local title = string.match(content, "<title>([^<]*)</title>") or ""
      local server = (response.header and response.header.server) or ""
      local auth = (response.header and response.header["www-authenticate"]) or ""
      local cookies = (response.header and response.header["set-cookie"]) or ""
      
      local all_text = content .. " " .. title .. " " .. server .. " " .. auth .. " " .. cookies
      
      if is_hanwha_device(all_text) then
        local result = {
          make = "Hanwha Vision",
          port = port.number,
          protocol = ssl and "https" or "http",
          path = path
        }
        
        result.model = extract_hanwha_model(all_text)
        
        if title and title ~= "" then
          result.title = title
        end
        
        if server and server ~= "" and is_hanwha_device(server) then
          result.server = server
        end
        
        -- Look for Wisenet branding
        if string.match(all_text, "[Ww]isenet") then
          result.brand = "Wisenet"
        end
        
        local versions = extract_versions(all_text)
        result.software_version = versions.software
        result.firmware_version = versions.firmware
        result.build_version = versions.build
        result.application_version = versions.application
        
        return result
      end
    end
  end
  
  return nil
end

-- RTSP detection
local function probe_rtsp(host, port)
  local socket = nmap.new_socket()
  local status, err
  
  socket:set_timeout(5000)
  
  status, err = socket:connect(host, port)
  if not status then
    socket:close()
    return nil
  end
  
  -- Send RTSP OPTIONS request
  local request = "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: NSE-Hanwha-Detect\r\n\r\n"
  
  status, err = socket:send(request)
  if not status then
    socket:close()
    return nil
  end
  
  local response
  status, response = socket:receive()
  socket:close()
  
  if status and response and is_hanwha_device(response) then
    local result = {
      make = "Hanwha Vision",
      port = port.number,
      protocol = "rtsp"
    }
    
    result.model = extract_hanwha_model(response)
    
    -- Look for Wisenet in RTSP response
    if string.match(response, "[Ww]isenet") then
      result.brand = "Wisenet"
    end
    
    local versions = extract_versions(response)
    result.software_version = versions.software
    result.firmware_version = versions.firmware
    
    return result
  end
  
  return nil
end

-- Main action function
action = function(host, port)
  local result = nil
  
  -- Use pcall to catch any errors and prevent script crashes
  local success, probe_result = pcall(function()
    if (port.service == "snmp" or port.number == 161) and port.protocol == "udp" then
      return probe_snmp(host, port)
    elseif (port.service == "sip" or port.number == 5060) then
      return probe_sip(host, port)
    elseif port.service == "rtsp" or port.number == 554 or port.number == 10554 then
      return probe_rtsp(host, port)
    elseif port.service == "https" or port.number == 443 then
      return probe_http(host, port, true)
    else
      return probe_http(host, port, false)
    end
  end)
  
  if success then
    result = probe_result
  else
    return nil
  end
  
  -- Format output only if Hanwha Vision device detected
  if result then
    local output_parts = {}
    
    -- Add make
    if result.make then
      table.insert(output_parts, result.make)
    end
    
    -- Add model
    if result.model then
      table.insert(output_parts, result.model)
    end
    
    -- Add version (prefer firmware, then software, then build)
    local version = result.firmware_version or result.software_version or result.build_version or result.application_version
    if version then
      table.insert(output_parts, version)
    end
    
    -- Join all parts with spaces and return as single line
    if #output_parts > 0 then
      return stdnse.format_output(true, {table.concat(output_parts, " ")})
    end
  end
  
  return nil
end
