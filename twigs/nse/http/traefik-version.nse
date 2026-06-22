local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[
Attempts to retrieve the Traefik reverse proxy version from its dashboard
API endpoint. The API is typically exposed on port 8080.
]]

---
-- @usage nmap --script traefik-version -p 8080 <target>
-- @output
-- 8080/tcp open  http
-- | traefik-version:
-- |_  traefik version: 2.10.4
-- @xmloutput
-- <elem key="traefik version">2.10.4</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({8080, 8081, 9000}, "tcp")

action = function(host, port)
  local response = http.get(host, port, "/api/version")
  if not response or not response.status or response.status ~= 200 or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data and data.Version then
    local result = stdnse.output_table()
    result["traefik version"] = data.Version
    return result
  end
end
