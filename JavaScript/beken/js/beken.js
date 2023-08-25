// JavaScript

const version = 'beken.js-002';
const start = performance.now();

// Get a reference to the container div
const container = document.getElementById('container');

const params = new URLSearchParams(location.search);
function router() {

  if (params.has('info')) {
      return showInfo();
  }

  var beken_host = localStorage.getItem("beken-host");
  if (!beken_host) {
      return viewAddPage();
  }

  return viewLanding();
}


function viewLanding() {
    document.title = 'Beken';

    // Create the Beken button and set up its click event
    const bekenButton = document.createElement('button');
    bekenButton.innerText = 'Beken';

    // Append the button to the container div
    container.appendChild(bekenButton);

    getPublicIP()
    .then(ip => {
        console.log('Your IP is:', ip);

        // Set the button's click event here after IP is obtained
        bekenButton.addEventListener('click', () => sendPostRequest(ip));

        // Create a div for the IP and append it
        const ipDiv = document.createElement('div');
        ipDiv.innerText = ip;
        container.appendChild(ipDiv);

    })
    .catch(error => {
        console.error('There was an error:', error);
    });
}

// This function will make the POST request
function sendPostRequest(ipAddress) {
    var beken_token = localStorage.getItem("beken-token");
    var beken_host = localStorage.getItem("beken-host");

    var headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append('beken-token', beken_token);

    var body = JSON.stringify({
        "ip": ipAddress  // Use the passed ipAddress instead of hard-coded value
    });

    var requestOptions = {
        method: 'POST',
        headers: headers,
        body: body
    };

    console.log(beken_host + "/beken/post");

    var timeoutDuration = 5000; // 5 seconds
    var timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error("Request timed out after " + timeoutDuration + "ms")), timeoutDuration);
    });

    Promise.race([fetch(beken_host + "/beken/post", requestOptions), timeoutPromise])
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(result => {
            document.getElementById('container').innerText = JSON.stringify(result);
        })
        .catch(error => {
            document.getElementById('container').innerText = 'Error: ' + error.message;
        });
}


function viewAddPage() {
    document.title = 'Beken:Add';

    let html = '';
    html += '<div><button id="addLocalItems">Add Beken</button></div>';

    container.innerHTML = html;

    document.getElementById("addLocalItems").addEventListener("click", addLocalItems, false);

    history.pushState({page: 'add'}, "add", "?add");
}


function showInfo() {

    let html = '';

    for (const a in localStorage) {
        //console.log(a, ' = ', localStorage[a]);
        html += '<div>' + a + '<input type="text" value="'+ localStorage[a] +'" disabled ></div>';
    }

    html += '<hr>';
    html += '<div><button onclick="addLocalStore()">Add Item</button>';
    html += '     <button onclick="localStorage.clear();location.reload();">Clear Storage</button>';
    html += '     <a href="?"><button>Home</button></a>';
    html += '</div>';

    container.innerHTML = html;

    history.pushState({page: 'info'}, "info", "?info");
}


window.addLocalStore = function() {
   const item_name  = window.prompt("name: ");
   const item_value = window.prompt("value: ");
   localStorage.setItem(item_name, item_value);
   history.pushState({page: 'addLocalStore'}, "addLocalStore", "?info=added");
   location.reload();
}


function addLocalItems() {
   const beken_token  = window.prompt("beken-token: ");
   const beken_host = window.prompt("beken-host: ");

   localStorage.setItem("beken-token", beken_token);
   localStorage.setItem("beken-host", beken_host);

   history.pushState({page: 'addLocalStore'}, "addLocalStore", "?");
   location.reload();
}


function getPublicIP() {

    var beken_token = localStorage.getItem("beken-token");
    var beken_host = localStorage.getItem("beken-host");

    //var ip_service_url = "https://api.ipify.org?format=json"
    var ip_service_url = beken_host + "/beken/ip"

    var ip_service = localStorage.getItem("ip-service");
    if (ip_service) {
        ip_service_url = ip_service
    } else {
        localStorage.setItem("ip-service", ip_service_url);
    }

    // Set up fetch options to include headers
    var fetchOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'beken-token': beken_token
        }
    };

    return fetch(ip_service_url, fetchOptions)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            return data.ip;
        });
}


let run = router();

const done = performance.now() - start;
console.log(version + ' ' + done);

