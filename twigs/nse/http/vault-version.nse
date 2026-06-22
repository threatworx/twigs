local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[Attempts to retrieve the HashiCorp Vault version via the sys/health endpoint.]]

---
-- @usage nmap --script vault-version -p 8200 <target>
-- @output
-- 8200/tcp open  https
-- | vault-version:
-- |_  vault version: 1.15.0
-- @xmloutput
-- <elem key="vault version">1.15.0</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({8200, 8201}, "tcp")

action = function(host, port)
  -- /v1/sys/health returns version even when sealed/standby
  local response = http.get(host, port, "/v1/sys/health")
  if not response or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data and data.version then
    local result = stdnse.output_table()
    result["vault version"] = data.version
    return result
  end
end
