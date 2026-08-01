const output = document.querySelector("#output");
const statusBadge = document.querySelector("#status");
const loginUsername = document.querySelector("#login-username");
const loginPassword = document.querySelector("#login-password");
const searchQuery = document.querySelector("#search-query");

function show(payload, label = "ok") {
  statusBadge.textContent = label;
  statusBadge.className = `tag ${payload.ok === false ? "danger" : "success"}`;
  output.textContent = JSON.stringify(payload, null, 2);
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    show(payload, "error");
    return;
  }
  show(payload, payload.mode || "ok");
}

document.querySelectorAll("[data-login]").forEach((button) => {
  button.addEventListener("click", () => {
    const mode = button.dataset.login;
    requestJson(`/api/login-${mode}`, {
      method: "POST",
      body: JSON.stringify({
        username: loginUsername.value,
        password: loginPassword.value,
      }),
    });
  });
});

document.querySelectorAll("[data-search]").forEach((button) => {
  button.addEventListener("click", () => {
    const mode = button.dataset.search;
    const q = encodeURIComponent(searchQuery.value);
    requestJson(`/api/users-${mode}?q=${q}`);
  });
});

document.querySelectorAll("[data-fill-login]").forEach((button) => {
  button.addEventListener("click", () => {
    loginUsername.value = button.dataset.fillLogin;
    loginPassword.value = "cualquier-cosa";
  });
});

document.querySelectorAll("[data-fill-credentials]").forEach((button) => {
  button.addEventListener("click", () => {
    const [username, password] = button.dataset.fillCredentials.split("|");
    loginUsername.value = username;
    loginPassword.value = password;
  });
});

document.querySelectorAll("[data-fill-search]").forEach((button) => {
  button.addEventListener("click", () => {
    searchQuery.value = button.dataset.fillSearch;
  });
});

document.querySelector("#reset-db").addEventListener("click", () => {
  requestJson("/api/reset", { method: "POST" });
});

document.querySelector("#load-schema").addEventListener("click", () => {
  requestJson("/api/schema");
});
