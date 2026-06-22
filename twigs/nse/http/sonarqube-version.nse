local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[Attempts to retrieve the SonarQube version via the system status API.]]

---
-- @usage nmap --script sonarqube-version -p 9000 <target>
-- @output
-- 9000/tcp open  http
-- | sonarqube-version:
-- |_  sonarqube version: 10.2.0.77647
-- @xmloutput
-- <elem key="sonarqube version">10.2.0.77647</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({9000, 9001}, "tcp")

action = function(host, port)
  local response = http.get(host, port, "/api/system/status")
  if not response or not response.status or response.status ~= 200 or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data and data.version then
    local result = stdnse.output_table()
    result["sonarqube version"] = data.version
    return result
  end
end
