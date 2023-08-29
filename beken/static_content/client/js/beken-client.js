// JavaScript
const start = performance.now();

const version = 'beken-client.js-0.0.0.🐕';

// Get a reference to the container div
const container = document.getElementById('container');

const params = new URLSearchParams(location.search);
function router() {

  var beken_token = localStorage.getItem("beken-token");
  if (!beken_token) {
      return addBekenToken();
  }

  if (params.has('info')) {
      return showInfo();
  }

  return viewLanding();
}


function viewLanding() {
    document.title = 'Beken:Client';

    // Create the Beken button and set up its click event
    const bekenButton = document.createElement('button');
    bekenButton.innerText = 'Beken';

    // Append the button to the container div
    container.appendChild(bekenButton);

    getPublicIP()
    .then(({ ip, exists }) => {
        console.log('Your IP is:', ip);
        console.log('Exists value is:', exists);

        // Set the button's click event here after IP is obtained
        bekenButton.addEventListener('click', () => sendPostRequest(ip));

        // Create a div for the IP and append it
        const ipDiv = document.createElement('div');
        ipDiv.innerText = `IP: ${ip} - Exists: ${exists}`;
        container.appendChild(ipDiv);

    })
    .catch(error => {
        console.error('There was an error:', error);
    });

    //setTimeout(function(){
    //    window.location.reload();
    //}, 30000); // 1000 1s

    const htmlH2 = document.createElement('h2');
    container.appendChild(htmlH2);

    // remove trailing slash
    if (window.location.pathname.endsWith("/")) {
        var newPath = window.location.pathname.slice(0, -1);
        window.history.replaceState({}, "", newPath);
    }

    let timer= 1;

    setInterval(() => {
        document.querySelector('h2').innerText= timer;
        timer++;
        if(timer > 30)
            location.reload();
    }, 1000);
}


// This function will make the POST request
function sendPostRequest(ipAddress) {
    var beken_token = localStorage.getItem("beken-token");
    //var beken_host = localStorage.getItem("beken-host");
    var beken_host = window.location.origin;

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


async function addBekenToken() {
  const beken_user  = window.prompt("user: ");
  const beken_pass  = window.prompt("pass: ");

  const text = beken_user + ":" + beken_pass;
  const encoder = new TextEncoder();
  const data = encoder.encode(text);

  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  // Convert buffer to byte array
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  // Convert the byte array to a Base64 string
  const base64 = btoa(String.fromCharCode(...hashArray));

  const beken_token = "bt-" + base64

  localStorage.setItem("beken-token", beken_token);
  history.pushState({page: 'addLocalStore'}, "addLocalStore", "?");
  location.reload();
}


function addBekenToken_V1() {
   const beken_token  = window.prompt("beken-token: ");
   localStorage.setItem("beken-token", beken_token);
   history.pushState({page: 'addLocalStore'}, "addLocalStore", "?");
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
    var beken_host = window.location.origin;

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
                //throw new Error('Network response was not ok');
                throw new Error(`Status ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            return {
                ip: data.ip,
                exists: data.exists
            };
        })
        .catch(error => {
            // Display the error message in the browser
            document.getElementById('container').innerText = error.message;
        });

}



//console.log(location.hostname);
//console.log(window.location.origin);
if (!window.location.origin) {
  window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port: '');
}

let run = router();

const done = performance.now() - start;
console.log(version + ' ' + done);


//  Get any piece of the url you're interested in
//url.hostname;  //  'example.com'
//url.port;      //  12345
//url.search;    //  '?startIndex=1&pageSize=10'
//url.pathname;  //  '/blog/foo/bar'
//url.protocol;  //  'http:'

