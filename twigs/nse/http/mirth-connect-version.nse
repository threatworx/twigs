local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"

description = [[Attempts to retrieve the Mirth Connect version from the REST API or login page.]]

---
-- @usage nmap --script mirth-connect-version -p 8443 <target>
-- @output
-- 8443/tcp open  https
-- | mirth-connect-version:
-- |_  mirth connect version: 4.4.1
-- @xmloutput
-- <elem key="mirth connect version">4.4.1</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({8443, 8080}, "tcp")

action = function(host, port)
  -- Mirth Connect REST API (v4+)
  local response = http.get(host, port, "/api/server/version",
    {header = {Accept = "application/json"}})
  if response and response.status == 200 and response.body then
    -- Response may be a plain version string or JSON
    local ver = string.match(response.body, '"([%d%.]+)"')
             or string.match(response.body, '^%s*([%d%.]+)%s*$')
    if ver then
      local result = stdnse.output_table()
      result["mirth connect version"] = ver
      return result
    end
  end
  -- Fallback: login page HTML
  response = http.get(host, port, "/webstart.jnlp")
  if response and response.status == 200 and response.body then
    local ver = string.match(response.body, "Mirth Connect ([%d%.]+)")
    if ver then
      local result = stdnse.output_table()
      result["mirth connect version"] = ver
      return result
    end
  end
end
