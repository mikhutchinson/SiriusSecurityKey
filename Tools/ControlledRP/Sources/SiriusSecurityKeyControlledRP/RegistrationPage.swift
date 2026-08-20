import Foundation

enum RegistrationPage {
  static let html = #"""
    <!doctype html>
    <html lang="en">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>SiriusSecurityKey Controlled RP</title>
    <style>
      body { font: 17px -apple-system, system-ui; max-width: 38rem; margin: 3rem auto; padding: 0 1rem; }
      input, button { font: inherit; padding: .65rem; margin: .35rem 0; }
      input { width: 100%; box-sizing: border-box; }
      button { width: 100%; }
      #status { min-height: 3rem; white-space: pre-wrap; }
    </style>
    <h1>Controlled RP registration</h1>
    <p>Open this page directly on the phone that will answer the cross-device QR.</p>
    <label>Declared device label<input id="label" maxlength="64" autocomplete="off"></label>
    <button id="register">Create required-UV discoverable ES256 credential</button>
    <p id="status" role="status"></p>
    <script>
      const b64decode = value => {
        const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
        return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
      };
      const b64encode = value => {
        let binary = '';
        for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
      };
      document.querySelector('#register').onclick = async () => {
        const status = document.querySelector('#status');
        const deviceLabel = document.querySelector('#label').value.trim();
        if (!deviceLabel) { status.textContent = 'Enter a device label.'; return; }
        try {
          status.textContent = 'Requesting server-owned challenge…';
          const optionsResponse = await fetch('/register/options', {
            method: 'POST', headers: {'content-type': 'application/json'},
            body: JSON.stringify({deviceLabel})
          });
          if (!optionsResponse.ok) throw new Error('options rejected');
          const envelope = await optionsResponse.json();
          const options = envelope.publicKey;
          options.challenge = b64decode(options.challenge);
          options.user.id = b64decode(options.user.id);
          options.excludeCredentials = options.excludeCredentials.map(item => ({...item, id: b64decode(item.id)}));
          status.textContent = 'Complete platform registration…';
          const credential = await navigator.credentials.create({publicKey: options});
          const finishResponse = await fetch('/register/finish', {
            method: 'POST', headers: {'content-type': 'application/json'},
            body: JSON.stringify({
              ceremonyID: envelope.ceremonyID,
              clientDataJSON: b64encode(credential.response.clientDataJSON),
              attestationObject: b64encode(credential.response.attestationObject),
              rawID: b64encode(credential.rawId)
            })
          });
          if (!finishResponse.ok) throw new Error('server verification rejected registration');
          status.textContent = 'Registration verified server-side. This phone is ready for assertion.';
        } catch (error) {
          status.textContent = `Registration failed: ${error.name || 'Error'}`;
        }
      };
    </script>
    </html>
    """#
}
