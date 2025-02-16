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
-- 8443/tcp open mirth connect 
-- |_mirth-connect-version: 4.5.0
--
-- @xmloutput
-- c<script id="mirth-connect-version" output="&#xa;  mirth connect: 4.5.0">
-- <elem key="mirth connect">4.5.0</elem>
-- </script>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.version_port_or_service({80,8080,443,8443}, {"mirth-connect-s"}, "tcp")

action = function(host, port)
  -- Perform a GET request for /server-status
  local path = "/api/server/version"
  local options = {header={}}
  options['header']['X-Requested-With'] = 'OpenAPI'
  options['redirect_ok'] = false 
  local response = http.get(host,port,path,options)
  local httpresponse = http.get(host,port,'/')
  local result = '' 
  local version = ''

  -- stdnse.debug(1, "version api output: %s", response.body)
  -- stdnse.debug(1, "html: %s", httpresponse.body)
  if response and string.match(response.body, "^%d") then
    version = response.body
  end

  stdnse.debug(1, "html: %s", string.match(httpresponse.body, "Mirth Connect")) 
  if httpresponse and string.match(httpresponse.body, "Mirth Connect") then
    result = stdnse.output_table()
    result["mirth connect"] = version 
    return result
  end
end
