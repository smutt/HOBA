/*
  The file is part of the Firefox HOBA client.
  
  HOBA client is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  HOBA client is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.

  Copyright (C) 2016, Andrew McConachie, <andrew@depht.com>
*/
// https://developer.mozilla.org/en-US/Add-ons/SDK/Tutorials/Display_a_Popup

self.port.on("show", function onShow(deviceID, keys){
  document.getElementById("h2-id").innerHTML = "Device Name: " + deviceID;

  // Is anyone using realm?
  displayRealm = false;
  for(var ii=0; ii<keys.length; ii++){
    if(keys[ii]['realm'].trim() != "" && keys[ii]['realm'] != null){
      displayRealm = true;
    }
  }

  var keyTable = "";
  if(displayRealm){
    keyTable += "<thead><tr><th>Site</th><th>Key Identifier</th><th>Realm</th></tr></thead><tbody>";
  }else{
    keyTable += "<thead><tr><th>Site</th><th>Key Identifier</th></tr></thead><tbody>";
  }
  for(var ii=0; ii<keys.length; ii++){
    keyTable += "<tr>";
    keyTable += "<td><h4>" + keys[ii]['site'].trim() + "</h4></td>";
    keyTable += "<td><h4>" + keys[ii]['kid'] + "</h4></td>";
    if(displayRealm){
      keyTable += "<td><h4>" + keys[ii]['realm'].trim() + "</h4></td>";
    }
    keyTable += "</tr>";
  }
  keyTable += "</tbody>";
  document.getElementById("table-id").innerHTML = keyTable;  
});

var devID = document.getElementById("input-id");
devID.addEventListener('keyup', function onkeyup(event){
  if(event.keyCode == 13){
    str = devID.value.trim();
    self.port.emit("finished", str);
  }
});
  
