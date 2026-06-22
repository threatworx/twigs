local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"
local string = require "string"

description = [[
Attempts to retrieve the Spring Boot application version via the actuator
info or health endpoints. Checks both /actuator/info (Spring Boot 2+) and
/info (Spring Boot 1.x). Also detects the presence of Spring Boot from the
X-Application-Context response header.
]]

---
-- @usage nmap --script spring-boot-version -p 8080 <target>
-- @output
-- 8080/tcp open  http
-- | spring-boot-version:
-- |_  spring boot version: 3.1.4
-- @xmloutput
-- <elem key="spring boot version">3.1.4</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.http

local function try_endpoint(host, port, path)
  local response = http.get(host, port, path)
  if not response or not response.status or response.status ~= 200 or not response.body then
    return nil
  end
  return response
end

action = function(host, port)
  -- Check for X-Application-Context header (Spring Boot 1.x)
  local response = http.get(host, port, "/")
  if response and response.header and response.header["x-application-context"] then
    local result = stdnse.output_table()
    result["spring boot application"] = response.header["x-application-context"]
    return result
  end

  -- Try /actuator/info (Spring Boot 2+)
  response = try_endpoint(host, port, "/actuator/info")
  if response then
    local ok, data = json.parse(response.body)
    if ok and data then
      -- Look for version in build info
      if data.build and data.build.version then
        local result = stdnse.output_table()
        result["spring boot version"] = data.build.version
        return result
      end
      -- Some apps expose app.version
      if data.app and data.app.version then
        local result = stdnse.output_table()
        result["spring boot version"] = data.app.version
        return result
      end
    end
    -- Even an accessible /actuator/info confirms Spring Boot
    if response.status == 200 then
      local result = stdnse.output_table()
      result["spring boot detected"] = "true"
      return result
    end
  end

  -- Try /info (Spring Boot 1.x default)
  response = try_endpoint(host, port, "/info")
  if response then
    local ok, data = json.parse(response.body)
    if ok and data and data.build and data.build.version then
      local result = stdnse.output_table()
      result["spring boot version"] = data.build.version
      return result
    end
  end

  -- Try /actuator/health for presence detection
  response = try_endpoint(host, port, "/actuator/health")
  if response then
    local ver = string.match(response.body or "", '"version"%s*:%s*"([^"]+)"')
    if ver then
      local result = stdnse.output_table()
      result["spring boot version"] = ver
      return result
    end
  end
end
