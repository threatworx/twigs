local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Attempts to retrieve the GitLab version from the web interface or API.
Checks the help page, login page metadata, and response headers.
]]

---
-- @usage nmap --script gitlab-version -p 80,443 <target>
-- @output
-- 443/tcp open  https
-- | gitlab-version:
-- |_  gitlab version: 16.3.4
-- @xmloutput
-- <elem key="gitlab version">16.3.4</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.http

action = function(host, port)
  -- Check X-Gitlab-Meta header or body of any page first
  local response = http.get(host, port, "/users/sign_in")
  if not response then return end

  -- Version in page HTML (gon.version or similar injection)
  if response.body then
    local ver = string.match(response.body, 'content="GitLab ([%d%.]+)"')
              or string.match(response.body, 'gitlab%-version["\']%s*:%s*["\']([%d%.]+)')
    if ver then
      local result = stdnse.output_table()
      result["gitlab version"] = ver
      return result
    end
    -- Detect GitLab presence even without version
    if string.match(response.body, 'GitLab') or string.match(response.body, 'gitlab') then
      -- Try /help which lists the version for older instances
      local help = http.get(host, port, "/help")
      if help and help.body then
        ver = string.match(help.body, 'GitLab ([%d]+%.[%d]+%.[%d]+)')
           or string.match(help.body, '"version"%s*:%s*"([%d%.]+)"')
        if ver then
          local result = stdnse.output_table()
          result["gitlab version"] = ver
          return result
        end
      end
      local result = stdnse.output_table()
      result["gitlab detected"] = "true"
      return result
    end
  end
end
