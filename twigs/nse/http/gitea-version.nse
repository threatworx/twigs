local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"
local string = require "string"

description = [[
Attempts to retrieve the Gitea or Forgejo version via the REST API or
response headers. Gitea exposes version at /api/v1/version (unauthenticated).
]]

---
-- @usage nmap --script gitea-version -p 3000 <target>
-- @output
-- 3000/tcp open  http
-- | gitea-version:
-- |_  gitea version: 1.21.1
-- @xmloutput
-- <elem key="gitea version">1.21.1</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.http

action = function(host, port)
  -- Gitea/Forgejo exposes version unauthenticated at /api/v1/version
  local response = http.get(host, port, "/api/v1/version")
  if response and response.status == 200 and response.body then
    local ok, data = json.parse(response.body)
    if ok and data and data.version then
      local result = stdnse.output_table()
      -- Forgejo is a Gitea fork; distinguish if possible
      local product = "gitea"
      local response2 = http.get(host, port, "/")
      if response2 and response2.body and string.match(response2.body, "[Ff]orgejo") then
        product = "forgejo"
      end
      result[product .. " version"] = data.version
      return result
    end
  end

  -- Fallback: check X-Gitea-Version or X-Forgejo-Version header
  response = http.get(host, port, "/")
  if response and response.header then
    local ver = response.header["x-gitea-version"] or response.header["x-forgejo-version"]
    if ver then
      local result = stdnse.output_table()
      result["gitea version"] = ver
      return result
    end
  end
end
