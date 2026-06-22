local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[Attempts to retrieve the Apache ActiveMQ version from the web console.]]

---
-- @usage nmap --script activemq-version -p 8161 <target>
-- @output
-- 8161/tcp open  http
-- | activemq-version:
-- |_  activemq version: 5.17.4
-- @xmloutput
-- <elem key="activemq version">5.17.4</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({8161, 8162}, "tcp")

action = function(host, port)
  local response = http.get(host, port, "/admin/")
  if not response or not response.status or not response.body then
    return
  end
  -- Try admin page (may redirect to login but still exposes version in body/title)
  local ver = string.match(response.body, "ActiveMQ (%d[%d%.]+)")
           or string.match(response.body, "activemq%-(%d[%d%.]+)")
  if ver then
    local result = stdnse.output_table()
    result["activemq version"] = ver
    return result
  end
  -- Try /api/jolokia for version info
  response = http.get(host, port, "/api/jolokia/read/org.apache.activemq:type=Broker,brokerName=localhost/BrokerVersion")
  if response and response.status == 200 and response.body then
    ver = string.match(response.body, '"value"%s*:%s*"(%d[%d%.]+)"')
    if ver then
      local result = stdnse.output_table()
      result["activemq version"] = ver
      return result
    end
  end
end
