local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[Attempts to retrieve the Grafana version via the /api/health endpoint.]]

---
-- @usage nmap --script grafana-version -p 3000 <target>
-- @output
-- 3000/tcp open  http
-- | grafana-version:
-- |_  grafana version: 10.1.5
-- @xmloutput
-- <elem key="grafana version">10.1.5</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({3000}, "tcp")

action = function(host, port)
  local response = http.get(host, port, "/api/health")
  if not response or not response.status or response.status ~= 200 or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data and data.version then
    local result = stdnse.output_table()
    result["grafana version"] = data.version
    return result
  end
end
