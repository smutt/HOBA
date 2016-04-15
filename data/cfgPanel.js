var table = document.getElementById("table-id");

self.port.on("show", function onShow(data) {
  table.innerHTML = "<table><th>Key</th><th>Site</th>";
  data.forEach(function(key){
    table.innerHTML += "<tr><td>" + key[0] + "</td><td>" + key[1] + "</td></tr>";    
  });
  table.innerHTML += "</table>";

  //  table.innerHTML = ss.storage.deviceID;
});
