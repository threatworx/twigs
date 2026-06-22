local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[Attempts to retrieve the etcd version via the /version endpoint.]]

---
-- @usage nmap --script etcd-version -p 2379 <target>
-- @output
-- 2379/tcp open  http
-- | etcd-version:
-- |_  etcd version: 3.5.9
-- @xmloutput
-- <elem key="etcd version">3.5.9</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({2379, 2380}, "tcp")

action = function(host, port)
  local response = http.get(host, port, "/version")
  if not response or not response.status or response.status ~= 200 or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data and data.etcdserver then
    local result = stdnse.output_table()
    result["etcd version"] = data.etcdserver
    return result
  end
end
