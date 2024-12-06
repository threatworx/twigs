local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"

description = [[
Attempts to retrieve the kibana version for webservers that
have the service running. 

]]


author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}


portrule = shortport.portnumber({5601},"tcp")


action = function(host, port)
  -- Perform a GET request for /
  local path = "/"
  local response = http.get(host,port,path)
  local result = '' 


  if not response or not response.status or not response.body then
    stdnse.debug(1, "Failed to retrieve: %s", path)
    stdnse.debug(1, "%s", response.body)
    return
  end


  for _,line in pairs(response.rawheader) do 
    if line:match("kbn%-version:") then
        _, temp = line.match(line, "([^,]+):([^,]+)")
        result = stdnse.output_table()
        result["kibana version number"] = temp
        return result 
      end
  end 
end 