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

function addHead(str){
  return "<th>" + str + "</th>";
}

function addCell(str){
  return "<td>" + str + "</td>";
}

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
    var headers = ["Site", "Key Identifier", "Realm"];
  }else{
    var headers = ["Site", "Key Identifier"];
  }

  keyTable += "<thead><tr>";
  headers.forEach( function(str){
    keyTable += addHead(str);
  });
  keyTable += "</tr></thead><tbody>";

  for(var ii=0; ii<keys.length; ii++){
    keyTable += "<tr>";
    keyTable += addCell(keys[ii]['site'].trim());
    keyTable += addCell(keys[ii]['kid']);
    if(displayRealm){
      keyTable += addCell(keys[ii]['realm'].trim())
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
  
