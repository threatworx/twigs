local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Attempts to detect Oracle WebLogic Server and retrieve its version from
the administration console login page or response headers.
]]

---
-- @usage nmap --script weblogic-version -p 7001 <target>
-- @output
-- 7001/tcp open  http
-- | weblogic-version:
-- |_  weblogic version: 14.1.1.0.0
-- @xmloutput
-- <elem key="weblogic version">14.1.1.0.0</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({7001, 7002, 7070, 7272, 9001}, "tcp")

action = function(host, port)
  local paths = {
    "/console/login/LoginForm.jsp",
    "/console/",
    "/wls-wsat/",
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.body then
      -- Version typically appears as "WebLogic Server 14.1.1.0.0" or similar
      local ver = string.match(response.body, "WebLogic Server ([%d]+%.[%d%.]+)")
               or string.match(response.body, "WebLogic/%s*([%d]+%.[%d%.]+)")
      if ver then
        local result = stdnse.output_table()
        result["weblogic version"] = ver
        return result
      end
      -- Detect WebLogic presence even without version
      if string.match(response.body, "WebLogic") or string.match(response.body, "weblogic") then
        local result = stdnse.output_table()
        -- Check X-Powered-By header
        local powered = response.header and (response.header["x-powered-by"] or "")
        ver = string.match(powered, "([%d]+%.[%d%.]+)")
        if ver then
          result["weblogic version"] = ver
        else
          result["weblogic detected"] = "true"
        end
        return result
      end
    end
    -- Check Server header
    if response and response.header and response.header["server"] then
      local ver = string.match(response.header["server"], "WebLogic/([%d%.]+)")
               or string.match(response.header["server"], "WebLogic ([%d%.]+)")
      if ver then
        local result = stdnse.output_table()
        result["weblogic version"] = ver
        return result
      end
    end
  end
end
