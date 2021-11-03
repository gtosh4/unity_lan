<script lang="ts">
  import { Browser, Events } from "@wailsapp/runtime";
  import { writable } from "svelte/store";
  import DeviceCheck from "./components/DeviceCheck.svelte";
  import GuildList from "./components/GuildList.svelte";

  enum loginState {
    Unknown,
    NeedsLogin,
    LoggedIn,
    LoginFailed,
  }

  let login = writable(loginState.Unknown);

  Events.On("doLogin", (loginURL) => {
    console.info("logging in");
    $login = loginState.NeedsLogin;
    Browser.OpenURL(loginURL);
  });

  Events.On("loggedIn", () => {
    console.info("logged in");
    $login = loginState.LoggedIn;
  });

  Events.On("loginFailed", () => {
    console.info("login failed");
    $login = loginState.LoginFailed;
  });
</script>

<main>
  <DeviceCheck />
  {#if $login == loginState.NeedsLogin}
    <p>Login with Discord (opened in browser)</p>
  {:else if $login == loginState.LoggedIn}
    <GuildList />
  {:else if $login == loginState.LoginFailed}
    <p>Login failed, check logs for details</p>
  {:else}
    <p>Waiting for login status from backend</p>
  {/if}
</main>

<style global>
  main {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto",
      "Oxygen", "Ubuntu", "Cantarell", "Fira Sans", "Droid Sans",
      "Helvetica Neue", sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }

  code {
    font-family: Fira Code, source-code-pro, Menlo, Monaco, Consolas,
      "Courier New", monospace;
  }
</style>
