
function updateStatus(text) {
    document.getElementById("message").innerHTML = text;
}

function updateExplanation(text) {
    document.getElementById('explanation').innerHTML = text;
}

async function enroll() {
    const publicKeyOptions = {

        rp: { name: "Auth test", id: "localhost" },
        user: { id: new Uint8Array([1]), name: "User 1", displayName: "User, Just User" },

        challenge: new Uint8Array([1, 2, 3, 4]),

        pubKeyCredParams: [{alg: -7, type: "public-key"}, {alg: -257, type: "public-key"}],
    };

    const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions
    });

    window.credential_id = credential.rawId;
    updateStatus("Created key " + credential.id)
}

async function login() {
    const options = {
        allowCredentials: [{
            id: window.credential_id,
            type: 'public-key'
        }],
        challenge: new Uint8Array([4, 5, 7, 8]),
    }

    const assertion = await navigator.credentials.get({
        publicKey: options
    });

    updateStatus("Authenticated user", new Uint8Array(assertion.response.userHandle)[0])
}

async function enrollServer(attachment) {
  const r1 = await fetch("/api/enroll/start?attachment=" + attachment, { method: 'POST' });
  const d1 = parseCreationOptionsFromJSON(await r1.json());
  const credential = await create(d1);

  const r2 = await fetch("/api/enroll/finish", {
    method: 'POST',
    headers: {
          "Content-Type": "application/json",
    },
    body: JSON.stringify(credential)
  });
  const d2 = await r2.json()
  updateStatus(d2.status)
  updateExplanation(JSON.stringify(d2.explanation, 0, 4))
}

async function loginServer() {
  const r1 = await fetch("/api/login/start", { method: 'POST' });
  const d1 = await r1.json();
  const credential = await get(parseRequestOptionsFromJSON(d1))
  const r2 = await fetch("/api/login/finish", {
    method: 'POST',
    headers: {
     "Content-Type": "application/json",
    },
    body: JSON.stringify(credential)
  });
  const d2 = await r2.json()

  updateStatus(d2.status)
  updateExplanation(JSON.stringify(d2.explanation, 0, 4))
}
