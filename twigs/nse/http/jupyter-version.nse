local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local json = require "json"
local string = require "string"

description = [[
Attempts to retrieve the Jupyter Notebook or JupyterLab version
via the /api endpoint (Notebook) or /lab/api (JupyterLab).
]]

---
-- @usage nmap --script jupyter-version -p 8888 <target>
-- @output
-- 8888/tcp open  http
-- | jupyter-version:
-- |_  jupyter version: 7.0.6
-- @xmloutput
-- <elem key="jupyter version">7.0.6</elem>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({8888, 8889, 8890}, "tcp")

action = function(host, port)
  -- Jupyter Notebook: GET /api returns {"version": "7.0.6", ...}
  local response = http.get(host, port, "/api")
  if response and response.status == 200 and response.body then
    local ok, data = json.parse(response.body)
    if ok and data and data.version then
      local result = stdnse.output_table()
      result["jupyter version"] = data.version
      return result
    end
  end

  -- JupyterHub: GET /hub/api
  response = http.get(host, port, "/hub/api")
  if response and response.status == 200 and response.body then
    local ok, data = json.parse(response.body)
    if ok and data and data.version then
      local result = stdnse.output_table()
      result["jupyterhub version"] = data.version
      return result
    end
  end

  -- Presence detection via title
  response = http.get(host, port, "/")
  if response and response.body then
    local is_jupyter = string.match(response.body, "[Jj]upyter")
    if is_jupyter then
      local ver = string.match(response.body, '"version"%s*:%s*"([%d%.]+)"')
      local result = stdnse.output_table()
      if ver then
        result["jupyter version"] = ver
      else
        result["jupyter detected"] = "true"
      end
      return result
    end
  end
end
