// JavaScript
const start = performance.now();

const version = 'beken-password.js-0.0.0.🐕';

// Get a reference to the container div
const container = document.getElementById('container');

const params = new URLSearchParams(location.search);
function router() {

  if (params.has('info')) {
      return showInfo();
  }

  return bekenPassWord();

  //return viewLanding();
}

async function bekenPassWord() {
  document.title = 'Beken:Password';
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

  const beken_token = "bt-" + base64;

  let keyStr;

  try {
      keyStr = await sendTokenRequest(beken_token);
  } catch (error) {
      document.getElementById('container').innerText = 'Error: ' + error.message;
      return;  // Stop the function if sendTokenRequest fails
  }

  const new_beken_pass  = window.prompt("new pass: ");

  const { base64Ciphertext, base64Iv } = await aesEncrypt(new_beken_pass, keyStr);
  console.log("Returned Base64 Ciphertext:", base64Ciphertext);
  console.log("Returned Base64 Iv:", base64Iv);

  postPassRequest(beken_user, beken_token, base64Ciphertext +" "+ base64Iv);

}


function postPassRequest(beken_user, beken_token, base64Ciphertext) {

    var headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append('beken-token', beken_token);

    var body = JSON.stringify({});

    var body = JSON.stringify({
        "user": beken_user,       // Use the passed var instead of hard-coded value
        "pass": base64Ciphertext  // Use the passed var instead of hard-coded value
    });

    var requestOptions = {
        method: 'POST',
        headers: headers,
        body: body
    };

    var beken_host = window.location.origin;

    console.log(beken_host + "/beken/pass");

    var timeoutDuration = 5000; // 5 seconds
    var timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error("Request timed out after " + timeoutDuration + "ms")), timeoutDuration);
    });

    Promise.race([fetch(beken_host + "/beken/pass", requestOptions), timeoutPromise])
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



// This function will make the POST request
async function sendTokenRequest(beken_token) {

  var headers = new Headers();
  headers.append('Content-Type', 'application/json');
  headers.append('beken-token', beken_token);

  var body = JSON.stringify({});

  var requestOptions = {
      method: 'POST',
      headers: headers,
      body: body
  };

  var beken_host = window.location.origin;

  console.log(beken_host + "/beken/token");

  var timeoutDuration = 5000; // 5 seconds
  var timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Request timed out after " + timeoutDuration + "ms")), timeoutDuration);
  });

  const response = await Promise.race([fetch(beken_host + "/beken/token", requestOptions), timeoutPromise]);

  if (!response.ok) {
    throw new Error(`HTTP error! Status: ${response.status}`);
  }

  const result = await response.json();
  document.getElementById('container').innerText = JSON.stringify(result);

  return result.key

}




async function aesEncrypt(text, keyStr) {

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(keyStr), // Use the key passed from the function parameter
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  //const iv = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

  const encryptedData = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    new TextEncoder().encode(text)
  );

  return {
    base64Ciphertext: btoa(String.fromCharCode(...new Uint8Array(encryptedData))),
    base64Iv: btoa(String.fromCharCode(...iv)),
  };
}

//const iv = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
//runEncrypt().catch(console.error);



// Convert an ArrayBuffer to a Base64 string
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}





function viewLanding() {
    document.title = 'Beken:Password';
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





//console.log(location.hostname);
//console.log(window.location.origin);
if (!window.location.origin) {
  window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port: '');
}

let run = router();

const done = performance.now() - start;
console.log(version + ' ' + done);
