local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Attempts to retrieve the Atlassian Confluence version for webservers that
have the service running. 

]]

---
--@usage nmap --script confluence-version.nse<target>
--
--@output
--PORT    STATE SERVICE
-- 80/tcp  open  http
-- 443/tcp open  https
-- | confluence-version:
-- |_  atlassian confluence version: 7.19.18
--
-- @xmloutput
-- <script id="confluence-version" output="&#xa;  atlassian confluence version: 7.19.18">
-- <elem key="atlassian confluence version">7.19.18</elem>
-- </script>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = function(host, port)
  if not shortport.http(host, port) then
    return false
  end
  return true
end

action = function(host, port)
  -- Perform a GET request for /server-status
  local path = "/"
  local response = http.get(host,port,path)
  local result = '' 

  if not response or not response.status or response.status ~= 200 or not response.body then
    stdnse.debug(1, "Failed to retrieve: %s", path)
    return
  end

  local acver = string.match(response.body, "information'>([0-9.]+)<") 
  if acver then
    result = stdnse.output_table()
    result["atlassian confluence version"] = acver
    return result
  end
end
