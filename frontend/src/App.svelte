<script lang="ts">
  import type { APIUser } from "discord-api-types";

  import DeviceCheck from "./components/DeviceCheck.svelte";
  import FriendList from "./components/FriendList.svelte";
  import { wailsStore } from "./wails_store";

  const login = wailsStore<APIUser>("LoginState");
</script>

<main>
  <DeviceCheck />
  {#if $login}
    <h1>Hello {$login.username} ({$login.id})</h1>
    <FriendList />
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
