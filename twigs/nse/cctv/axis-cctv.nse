local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local nmap = require "nmap"

description = [[
Detects Axis camera devices using FTP banner analysis.
Returns a single line with make, model, and firmware version if available.
]]

---
-- @usage
-- nmap --script axis-detect -p 21 <target>
--
-- @output
-- Host script results:
-- | axis-detect: 
-- |_  AXIS P1435-LE Network Camera v10.12.193
--
-- @args axis-detect.timeout Timeout for FTP banner check (default: 5s)

author = "Assistant"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Only check FTP port
portrule = shortport.port_or_service(21, "ftp")

-- FTP banner patterns for Axis devices
local ftp_patterns = {
    -- Common Axis FTP banner patterns
    "220%s+AXIS%s+([%w%-%.%s]+)%s+FTP",
    "220%s+([%w%-%.%s]*AXIS[%w%-%.%s]*)%s+FTP",
    "220%s+FTP%s+server%s+%(AXIS%s+([%w%-%.%s]+)%)",
    "220%-+%s*AXIS%s+([%w%-%.%s]+)",
    "220%s+([%w%-%.%s]+)%s+Network%s+Camera%s+FTP",
    -- Version patterns
    "Version%s+([%d%.%-]+)",
    "v([%d%.%-]+)",
    "firmware%s+([%d%.%-]+)"
}

-- Extract model and firmware from banner
local function parse_ftp_banner(banner)
    if not banner or not banner:upper():find("AXIS") then
        return nil
    end
    local extracted = banner:match("220%s+(.-)%s+%(")
    return extracted    
end

-- FTP banner detection
local function check_ftp_banner(host, port)
    local socket = nmap.new_socket()
    
    local status, err = socket:connect(host, port)
    if not status then
        socket:close()
        return nil
    end
    
    -- Read FTP banner
    local status, banner = socket:receive_lines(1)
    socket:close()
    
    if status and banner then
        return parse_ftp_banner(banner)
    end
    
    return nil
end

-- Main action function
action = function(host, port)
    local device = check_ftp_banner(host, port)
    
    -- If we found an Axis device, format the output
    if device and device:upper():find("AXIS") then
        return device 
    end
    
    return nil
end
