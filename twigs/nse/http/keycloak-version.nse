local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"
local string = require "string"

description = [[
Attempts to detect Keycloak and retrieve its version. Checks the
OpenID Connect well-known endpoint and admin console response headers.
]]

---
-- @usage nmap --script keycloak-version -p 8080 <target>
-- @output
-- 8080/tcp open  http
-- | keycloak-version:
-- |_  keycloak version: 22.0.3
-- @xmloutput
-- <elem key="keycloak version">22.0.3</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.http

action = function(host, port)
  -- Keycloak 17+ (Quarkus): /realms/master endpoint
  local response = http.get(host, port, "/realms/master")
  if response and response.status == 200 and response.body then
    local ok, data = json.parse(response.body)
    if ok and data and (data.realm or data["token-service"]) then
      -- Confirmed Keycloak; try to get version from welcome page or header
      local ver = nil
      local welcome = http.get(host, port, "/")
      if welcome and welcome.body then
        ver = string.match(welcome.body, 'Keycloak ([%d]+%.[%d]+%.[%d%.]+)')
           or string.match(welcome.body, '"version"%s*:%s*"([%d%.]+)"')
      end
      -- Check X-Frame-Options or Server header for clues
      if not ver and response.header then
        ver = response.header["x-keycloak-version"]
      end
      local result = stdnse.output_table()
      if ver then
        result["keycloak version"] = ver
      else
        result["keycloak detected"] = "true"
      end
      return result
    end
  end

  -- Keycloak 16 and below: /auth/realms/master
  response = http.get(host, port, "/auth/realms/master")
  if response and response.status == 200 and response.body then
    local ok, data = json.parse(response.body)
    if ok and data and (data.realm or data["token-service"]) then
      local result = stdnse.output_table()
      result["keycloak detected"] = "true"
      return result
    end
  end
end
