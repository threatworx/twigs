local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[
Attempts to retrieve the Portainer container management platform version
via the /api/status endpoint which is unauthenticated.
]]

---
-- @usage nmap --script portainer-version -p 9000 <target>
-- @output
-- 9000/tcp open  http
-- | portainer-version:
-- |_  portainer version: 2.19.4
-- @xmloutput
-- <elem key="portainer version">2.19.4</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({9000, 9001, 9443, 8000}, "tcp")

action = function(host, port)
  local response = http.get(host, port, "/api/status")
  if not response or not response.status or response.status ~= 200 or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data and data.Version then
    local result = stdnse.output_table()
    result["portainer version"] = data.Version
    if data.ProductEdition then
      result["portainer edition"] = data.ProductEdition
    end
    return result
  end
end
