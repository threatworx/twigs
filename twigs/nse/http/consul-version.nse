local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[Attempts to retrieve the HashiCorp Consul version via the agent API.]]

---
-- @usage nmap --script consul-version -p 8500 <target>
-- @output
-- 8500/tcp open  http
-- | consul-version:
-- |_  consul version: 1.16.1
-- @xmloutput
-- <elem key="consul version">1.16.1</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({8500, 8501}, "tcp")

action = function(host, port)
  local response = http.get(host, port, "/v1/agent/self")
  if not response or not response.status or response.status ~= 200 or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data then
    local ver = nil
    if data.Config and data.Config.Version then
      ver = data.Config.Version
    elseif data.config and data.config.Version then
      ver = data.config.Version
    end
    if ver then
      local result = stdnse.output_table()
      result["consul version"] = ver
      return result
    end
  end
end
