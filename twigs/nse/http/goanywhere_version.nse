local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects GoAnywhere Managed File Transfer (MFT) software and extracts version information.
]]

author = "NSE Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = function(host, port)
  return (shortport.http(host, port) or shortport.ssl(host, port))
end

action = function(host, port)
  local path = "/"
  local options = {
    header = {
      ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
  }
  
  local response = http.get(host, port, path, options)
  
  if not response or not response.status or response.status ~= 200 then
    return nil
  end
  
  local body = response.body
  if not body then
    return nil
  end
  
  -- Check for GoAnywhere signature
  if not string.match(body, "GoAnywhere") then
    return nil
  end
  
  -- Extract version using pattern matching
  local version = string.match(body, "GoAnywhere%s+([%d%.]+)%s*%-")
  
  if version then
    return "fortra goanywhere managed file transfer " .. version
  end
  
  return nil
end
