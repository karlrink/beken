// JavaScript
const start = performance.now();

const version = 'beken-password.js-1.0.0.🐕-2023-08-30';

// Get a reference to the container div
const container = document.getElementById('container');

const params = new URLSearchParams(location.search);
function router() {

  if (params.has('info')) {
      return showInfo();
  }

  return bekenPassWord();

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

  // Create a URL-safe Base64 string
  //const base64UrlSafe = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const beken_token = "bt-" + base64;

  let results;

  try {
      results = await tokenRequest(beken_token, beken_user);
  } catch (error) {
      document.getElementById('container').innerText = 'Error: ' + error.message;
      return;  // Stop the function if sendTokenRequest fails
  }
  //console.log(results.key);
  //console.log(results.id);

  const new_beken_pass  = window.prompt("new pass: ");

  //gen new_local_token
  const text2 = beken_user + ":" + new_beken_pass;
  const encoder2 = new TextEncoder();
  const data2 = encoder.encode(text2);
  const hashBuffer2 = await crypto.subtle.digest('SHA-256', data2);
  const hashArray2 = Array.from(new Uint8Array(hashBuffer2));
  const base64_2 = btoa(String.fromCharCode(...hashArray2));
  const beken_token2 = "bt-" + base64_2;

  const { base64Ciphertext, base64Iv } = await aesEncrypt(new_beken_pass, results.key);
  //console.log("Returned Base64 Ciphertext:", base64Ciphertext);
  //console.log("Returned Base64 Iv:", base64Iv);
    
  //postPassRequest(beken_user, beken_token, base64Ciphertext, base64Iv, result.id);

    let server_token = "BekenToken";  // Declare new_token here
    try {
        //server_token = await postPassRequest(beken_user, beken_token, base64Ciphertext, base64Iv, results.id);  // Assign new_token directly
        server_token = await postPassRequest(beken_user, beken_token, beken_token2, base64Ciphertext, base64Iv, results.id);
        console.log(beken_token2);
        console.log(server_token);

        localStorage.setItem("beken-token", beken_token2);

        //history.pushState({page: 'beken:password'}, "beken:password", "?");
        //location.reload();
        
        window.location.href = "/beken/client";

        
    } catch (error) {
        document.getElementById('container').innerText = 'Error: ' + error.message;
        console.log("hello broken token");
        console.log(server_token);  // This will output "BekenToken" if an error occurs
        return;
    }

}

function postPassRequest(beken_user, beken_token, new_beken_token, base64Ciphertext, base64Iv, keyId) {
    return new Promise(async (resolve, reject) => {
        // ... (the rest of your code remains the same up to the fetch call)

    var headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append('beken-token', beken_token);

    var body = JSON.stringify({});

    //var pass = base64Ciphertext + " " + base64Iv;

    var body = JSON.stringify({  // Use the passed var instead of hard-coded value
        "user": beken_user,
        "crypt": base64Ciphertext,
        "iv": base64Iv,
        "token": new_beken_token,
        "id": keyId
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

        
        try {
            const response = await Promise.race([fetch(beken_host + "/beken/pass", requestOptions), timeoutPromise]);
            if (!response.ok) {
                reject(new Error(`HTTP error! Status: ${response.status}`));
            }
            const result = await response.json();
            resolve(result['beken-token']);  // Resolve promise with the 'beken-token'
        } catch (error) {
            reject(error);
        }


    });

}




// This function will make the POST request
async function tokenRequest(beken_token, beken_user) {

  var headers = new Headers();
  headers.append('Content-Type', 'application/json');
  headers.append('beken-token', beken_token);
  headers.append('beken-user', beken_user);

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

  return { key: result.key, id: result.id };

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
