local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[Attempts to retrieve the Sonatype Nexus Repository Manager version.]]

---
-- @usage nmap --script nexus-version -p 8081 <target>
-- @output
-- 8081/tcp open  http
-- | nexus-version:
-- |_  nexus version: 3.61.0-02
-- @xmloutput
-- <elem key="nexus version">3.61.0-02</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({8081}, "tcp")

action = function(host, port)
  -- Nexus 3 REST API status
  local response = http.get(host, port, "/service/rest/v1/status/check")
  if response and response.header and response.header["server"] then
    local ver = string.match(response.header["server"], "Nexus/(%S+)")
    if ver then
      local result = stdnse.output_table()
      result["nexus version"] = ver
      return result
    end
  end
  -- Fallback: parse the HTML page for version string
  response = http.get(host, port, "/")
  if response and response.status == 200 and response.body then
    local ver = string.match(response.body, "Nexus Repository Manager (%d[%d%.%-]+)")
             or string.match(response.body, '"version"%s*:%s*"(%d[%d%.%-]+)"')
    if ver then
      local result = stdnse.output_table()
      result["nexus version"] = ver
      return result
    end
  end
end
