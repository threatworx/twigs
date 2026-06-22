local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[Attempts to retrieve the Prometheus version via the build-info API.]]

---
-- @usage nmap --script prometheus-version -p 9090 <target>
-- @output
-- 9090/tcp open  http
-- | prometheus-version:
-- |_  prometheus version: 2.47.1
-- @xmloutput
-- <elem key="prometheus version">2.47.1</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({9090, 9091}, "tcp")

action = function(host, port)
  local response = http.get(host, port, "/api/v1/status/buildinfo")
  if not response or not response.status or response.status ~= 200 or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data and data.status == "success" and data.data and data.data.version then
    local result = stdnse.output_table()
    result["prometheus version"] = data.data.version
    return result
  end
end
