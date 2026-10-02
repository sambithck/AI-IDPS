function getToken() {
  return localStorage.getItem("idps_token");
}

function getRole() {
  return localStorage.getItem("idps_role");
}

function requireAuth() {
  var token = getToken();
  if (!token) {
    window.location.href = "/login";
  }
}

async function apiFetch(path, options) {
  options = options || {};
  var token = getToken();
  var headers = Object.assign(
    {"Content-Type": "application/json"},
    options.headers || {},
    token ? {Authorization: "Bearer " + token} : {}
  );
  var resp = await fetch(path, Object.assign({}, options, {headers: headers}));
  if (resp.status === 401) {
    localStorage.removeItem("idps_token");
    window.location.href = "/login";
    return null;
  }
  return resp;
}

function logout() {
  localStorage.removeItem("idps_token");
  localStorage.removeItem("idps_role");
  localStorage.removeItem("idps_username");
  window.location.href = "/login";
}
