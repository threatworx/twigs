local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Attempts to retrieve the Apache Tomcat version for webservers that
have the service running. 

]]

---
--@usage nmap --script tomcat-version.nse<target>
--
--@output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | tomcat-version:
-- |_  apache tomcat version: 9.0.80
--
-- @xmloutput
-- <script id="tomcat-version" output="&#xa;  apache tomcat version: 9.0.80">
-- <elem key="apache tomcat version">9.0.80</elem>
-- </script>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = function(host, port)
  if not shortport.http(host, port) then
    return false
  end
  return true
end

action = function(host, port)
  -- Perform a GET request for /server-status
  local path = "/dummy-get-fail"
  local response = http.get(host,port,path)
  local result = '' 

  if not response or not response.status or response.status ~= 404 or not response.body then
    stdnse.debug(1, "Failed to retrieve: %s", path)
    return
  end

  local tcver = string.match(response.body, "Apache Tomcat/([a-zA-Z.0-9-]+)") 
  if tcver then
    result = stdnse.output_table()
    result["apache tomcat version"] = tcver
    return result
  end
end
