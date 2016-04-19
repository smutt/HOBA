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
  
