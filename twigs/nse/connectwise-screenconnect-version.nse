local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Attempts to retrieve version for Connectwise ScreenConnect application 

]]

---
--@usage nmap --script connectwise-screenconnect-version.nse<target>
--
--@output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | connectwise-screenconnect-version: 
-- |_  connectwise screenconnect: 23.9.8.8811-2863243764--
-- @xmloutput
-- script id="connectwise-screenconnect-version" output="&#xa;  connectwise screenconnect: 23.9.8.8811-2863243764">
-- <elem key="connectwise screenconnect">23.9.8.8811-2863243764</elem>
-- </script>

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({80,443,8080,8443})

action = function(host, port)
  -- Perform a GET request for /
  local path = "/"
  local response = http.get(host,port,path)
  local result = '' 

  if not response or not response.status or response.status ~= 200 or not response.body then
    stdnse.debug(1, "Failed to retrieve: %s", path)
    stdnse.debug(1, "%s", response.body)
    return
  end

  if response.header['server'] then
    local scver = string.match(response.header['server'], "ScreenConnect/([a-zA-Z.0-9-]+)")	  
    if scver then
      result = stdnse.output_table()
      result["connectwise screenconnect"] = scver
      return result
    end
  end
end
