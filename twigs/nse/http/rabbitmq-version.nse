local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"

description = [[Attempts to retrieve the RabbitMQ version via the management API overview endpoint.]]

---
-- @usage nmap --script rabbitmq-version -p 15672 <target>
-- @output
-- 15672/tcp open  http
-- | rabbitmq-version:
-- |_  rabbitmq version: 3.12.4
-- @xmloutput
-- <elem key="rabbitmq version">3.12.4</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({15672, 15671}, "tcp")

action = function(host, port)
  -- /api/overview requires auth by default; try guest:guest (common default)
  local response = http.get(host, port, "/api/overview",
    {auth = {username = "guest", password = "guest"}})
  if not response or not response.status or response.status ~= 200 or not response.body then
    -- Try unauthenticated — some installs allow it
    response = http.get(host, port, "/api/overview")
  end
  if not response or not response.status or response.status ~= 200 or not response.body then
    return
  end
  local ok, data = json.parse(response.body)
  if ok and data and data.rabbitmq_version then
    local result = stdnse.output_table()
    result["rabbitmq version"] = data.rabbitmq_version
    return result
  end
end
