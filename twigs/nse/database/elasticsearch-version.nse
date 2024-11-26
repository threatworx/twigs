local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"

description = [[
Attempts to retrieve the elasticsearch version for webservers that
have the service running. 

]]


author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = shortport.portnumber({9200,9300},"tcp")

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

  local data, var = json.parse(response.body)
  
  if data then 
    result = stdnse.output_table()
    result["elasticsearch version number"] = var.version.number  
    result["luceneversion number"] = var.version.lucene_version
    return result 
  else 
    return "Version information not found."
  end 
end 