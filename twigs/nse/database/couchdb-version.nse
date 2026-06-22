local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[Attempts to retrieve the Apache CouchDB version from the root endpoint.]]

---
-- @usage nmap --script couchdb-version -p 5984 <target>
-- @output
-- 5984/tcp open  http
-- | couchdb-version:
-- |_  couchdb version: 3.3.2
-- @xmloutput
-- <elem key="couchdb version">3.3.2</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({5984, 6984}, "tcp")

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response or not response.status or response.status ~= 200 or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data and data.version then
    local result = stdnse.output_table()
    result["couchdb version"] = data.version
    return result
  end
end
