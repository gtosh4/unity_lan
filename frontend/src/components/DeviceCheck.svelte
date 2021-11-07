<script lang="ts">
  import { Card } from "smelte";
  import { wailsStore } from "../wails_store";

  type DeviceStatus = "no_device" | "ok";

  const status = wailsStore<DeviceStatus>("WGDevice");
</script>

{#if $status != "ok"}
  <Card.Card classes="bg-error-800 w-full">
    <div slot="title">
      <Card.Title title="No Wireguard Device setup" />
    </div>
    <div slot="text">
      <ol class="list-decimal">
        <li>
          Make sure <a href="https://www.wireguard.com/install/">Wireguard</a> is
          installed
        </li>
        <li>
          Create a device (tunnel) with name <pre>unity_wg0</pre>
        </li>
      </ol>
    </div>
  </Card.Card>
{/if}

<style global>
</style>
