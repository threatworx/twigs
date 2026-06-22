local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[Attempts to retrieve the InfluxDB version (1.x via ping header, 2.x via health endpoint).]]

---
-- @usage nmap --script influxdb-version -p 8086 <target>
-- @output
-- 8086/tcp open  http
-- | influxdb-version:
-- |_  influxdb version: 2.7.1
-- @xmloutput
-- <elem key="influxdb version">2.7.1</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({8086}, "tcp")

action = function(host, port)
  -- InfluxDB 1.x exposes version in X-Influxdb-Version response header on /ping
  local response = http.get(host, port, "/ping")
  if response and response.header then
    local ver = response.header["x-influxdb-version"]
    if ver then
      local result = stdnse.output_table()
      result["influxdb version"] = ver
      return result
    end
  end
  -- InfluxDB 2.x exposes version via /health JSON body
  response = http.get(host, port, "/health")
  if response and response.status == 200 and response.body then
    local ok, data = json.parse(response.body)
    if ok and data and data.version then
      local result = stdnse.output_table()
      result["influxdb version"] = data.version
      return result
    end
  end
end
