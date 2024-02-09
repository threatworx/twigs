local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Attempts to retrieve version for Mirth Connect application 

]]

---
--@usage nmap --script tomcat-version.nse<target>
--
--@output
-- PORT     STATE SERVICE
-- 8443/tcp open  Mirth Connect
-- |_mirth-connect-version: 4.5.0
--
-- @xmloutput
-- c<script id="mirth-connect-version" output="&#xa;  Mirth Connect: 4.5.0">
-- <elem key="Mirth Connect">4.5.0</elem>
-- </script>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery,safe"}

portrule = shortport.version_port_or_service({8443}, {"mirth-connect-s"}, "tcp")

action = function(host, port)
  -- Perform a GET request for /server-status
  local path = "/api/server/version"
  local options = {header={}}
  options['header']['X-Requested-With'] = 'OpenAPI'
  local response = http.get(host,port,path,options)
  local result = '' 

  if not response or not response.status or response.status ~= 200 or not response.body then
    stdnse.debug(1, "Failed to retrieve: %s", path)
    stdnse.debug(1, "%s", response.body)
    return
  end

  result = stdnse.output_table()
  result["Mirth Connect"] = response.body 
  return result
end
