description = [[
Detects if a Jira instance (Cloud or Server/Data Center) is running by querying known endpoints.
Attempts to identify Jira version, build number, and deployment type (Cloud vs Server).
]]

---
-- @usage
-- nmap --script=jira-advanced-detect -p80,443 <target>
--
-- @output
-- 443/tcp open  https
-- | jira-version:
-- |   jira version: 9.4.2
---

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

-- Helper function to check for Jira Cloud indicators
local function is_jira_cloud(headers, body)
  if not headers then return false end
  if headers["X-AREQUESTID"] and headers["X-ATLASSIAN-TRACKING-ID"] then
    return true
  end
  if body and body:match("Atlassian Cloud") then
    return true
  end
  if headers["Server"] and headers["Server"]:lower():match("atlassianproxy") then
    return true
  end
  return false
end

action = function(host, port)
  local endpoints = {
    "/rest/api/2/serverInfo",
    "/status",
    "/login.jsp"
  }

  for _, path in ipairs(endpoints) do
    local response = http.get(host, port, path)

    if response and response.status and response.status ~= 404 then
      local cloud = is_jira_cloud(response.header, response.body)

      -- Attempt JSON parsing safely
      if response.status == 200 and response.body and response.body:match("version") then
        local acver = string.match(response.body, 'version":"([0-9.]+)') 
        if acver then
          result = stdnse.output_table()
          result["jira version"] = acver
          return result
        end
      end

      -- Fallback: check for Jira indicators in login/status page
      if response.status == 200 or response.status == 302 or response.status == 401 then
        local body = response.body or ""
        if body:match("[Jj]ira") or body:match("Atlassian") or cloud then
          return cloud and "Jira detected (Cloud) via " .. path or "Jira detected (Server) via " .. path
        end
      end
    end
  end

  return nil
end

